/**
 * Environment configuration for the hosted (Vercel + Supabase) deployment.
 */

import { privacyModeSchema, type PrivacyMode } from "../privacy.js";
import {
  MIN_CONNECTOR_PASSWORD_LENGTH,
  parseAllowedRedirectUris,
  validatePublicUrl,
} from "../transport/oauth-helpers.js";
import type { LogLevel } from "../logging/logger.js";

/** Minimum MCP_AUTH_TOKEN length — it also seeds the JWT and encryption keys. */
export const MIN_AUTH_TOKEN_LENGTH = 32;

/** Claude's OAuth callback URLs (web, desktop and mobile share these). */
export const DEFAULT_ALLOWED_REDIRECT_URIS = [
  "https://claude.ai/api/mcp/auth_callback",
  "https://claude.com/api/mcp/auth_callback",
];

export interface HostedConfig {
  whoopClientId: string;
  whoopClientSecret: string;
  supabaseUrl: string;
  supabaseServiceKey: string;
  /** Static bearer for header-based clients (Claude Code, Cursor, curl). */
  authToken: string;
  /** Password guarding the connector login and the WHOOP connect page. */
  connectorPassword: string;
  /** Public https origin without trailing slash, e.g. https://whoop.example.com */
  publicUrl: string;
  allowedRedirectUris: string[];
  oauthClientId: string;
  /** Explicit JWT secret; derived from authToken when unset. */
  jwtSecret?: string;
  /** Secret for encrypting WHOOP tokens at rest; defaults to authToken. */
  tokenEncryptionSecret: string;
  allowedOrigins: string[];
  privacyMode: PrivacyMode;
  disableResources: boolean;
  logLevel: LogLevel;
}

type Env = Record<string, string | undefined>;

function list(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function resolvePublicUrl(env: Env): string | undefined {
  if (env.PUBLIC_URL) return env.PUBLIC_URL;
  // Vercel system env var — the stable production domain (no protocol).
  if (env.VERCEL_PROJECT_PRODUCTION_URL) return `https://${env.VERCEL_PROJECT_PRODUCTION_URL}`;
  return undefined;
}

/**
 * Parse and validate hosted configuration. Collects every problem before
 * throwing so a misconfigured deployment can be fixed in one pass. Error
 * messages name variables only — never their values.
 */
export function parseHostedConfig(env: Env): HostedConfig {
  const problems: string[] = [];
  const required = (name: string): string => {
    const value = env[name];
    if (!value) problems.push(`${name} is required.`);
    return value ?? "";
  };

  const whoopClientId = required("WHOOP_CLIENT_ID");
  const whoopClientSecret = required("WHOOP_CLIENT_SECRET");
  const supabaseUrl = required("SUPABASE_URL");
  const supabaseServiceKey = env.SUPABASE_SERVICE_ROLE_KEY ?? env.SUPABASE_SECRET_KEY ?? "";
  if (!supabaseServiceKey) {
    problems.push("SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_SECRET_KEY) is required.");
  }

  const authToken = required("MCP_AUTH_TOKEN");
  if (authToken && authToken.length < MIN_AUTH_TOKEN_LENGTH) {
    problems.push(`MCP_AUTH_TOKEN must be at least ${MIN_AUTH_TOKEN_LENGTH} characters.`);
  }

  const connectorPassword = required("MCP_CONNECTOR_PASSWORD");
  if (connectorPassword && connectorPassword.length < MIN_CONNECTOR_PASSWORD_LENGTH) {
    problems.push(
      `MCP_CONNECTOR_PASSWORD must be at least ${MIN_CONNECTOR_PASSWORD_LENGTH} characters.`
    );
  }

  let publicUrl = "";
  const rawPublicUrl = resolvePublicUrl(env);
  if (!rawPublicUrl) {
    problems.push("PUBLIC_URL is required (or deploy on Vercel to infer it).");
  } else {
    try {
      publicUrl = validatePublicUrl(rawPublicUrl).origin;
    } catch (error) {
      problems.push(error instanceof Error ? error.message : "PUBLIC_URL is invalid.");
    }
  }

  if (supabaseUrl) {
    try {
      if (new URL(supabaseUrl).protocol !== "https:")
        problems.push("SUPABASE_URL must use https://.");
    } catch {
      problems.push("SUPABASE_URL is not a valid URL.");
    }
  }

  const privacy = privacyModeSchema.safeParse(env.WHOOP_MCP_PRIVACY_MODE ?? "standard");
  if (!privacy.success) problems.push("WHOOP_MCP_PRIVACY_MODE must be standard or aggregate.");

  const rawLogLevel = (env.LOG_LEVEL ?? "info").toLowerCase();
  const logLevel: LogLevel =
    rawLogLevel === "debug" || rawLogLevel === "warn" || rawLogLevel === "error"
      ? rawLogLevel
      : "info";

  if (problems.length > 0) {
    throw new Error(`Invalid server configuration:\n- ${problems.join("\n- ")}`);
  }

  const redirectUris = parseAllowedRedirectUris(env.ALLOWED_REDIRECT_URIS);

  return {
    whoopClientId,
    whoopClientSecret,
    supabaseUrl,
    supabaseServiceKey,
    authToken,
    connectorPassword,
    publicUrl,
    allowedRedirectUris: redirectUris.length > 0 ? redirectUris : DEFAULT_ALLOWED_REDIRECT_URIS,
    oauthClientId: env.MCP_OAUTH_CLIENT_ID ?? "whoop-mcp-connector",
    ...(env.MCP_JWT_SECRET ? { jwtSecret: env.MCP_JWT_SECRET } : {}),
    tokenEncryptionSecret: env.WHOOP_TOKEN_ENCRYPTION_KEY ?? authToken,
    allowedOrigins: list(env.MCP_ALLOWED_ORIGINS),
    privacyMode: privacy.success ? privacy.data : "standard",
    disableResources: env.WHOOP_MCP_DISABLE_RESOURCES === "1",
    logLevel,
  };
}
