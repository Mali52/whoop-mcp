/**
 * Serverless request handler for the hosted (Vercel + Supabase) deployment.
 *
 * One Node `(req, res)` function serves every route:
 *   GET  /                    — landing page with setup links
 *   GET  /health              — liveness (+ WHOOP link status with bearer)
 *   *    /whoop/connect|callback — WHOOP account linking (browser)
 *   *    /authorize, /token, /.well-known/* — OAuth 2.1 connector for Claude
 *   POST /mcp                 — MCP Streamable HTTP, stateless JSON responses
 *
 * The MCP transport runs in stateless mode: a fresh server + transport per
 * request, no session IDs, no long-lived SSE streams — every request can land
 * on a different instance. All shared state lives in Supabase.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { createWhoopClient, type WhoopClient, type WhoopGetOptions } from "../api/client.js";
import { MemoryCache } from "../cache/memory-cache.js";
import { createWhoopServer } from "../server.js";
import {
  extractBearerToken,
  handleCors,
  readBody,
  safeTokenCompare,
  sendJson,
} from "../transport/http.js";
import { createOAuthApp } from "../transport/oauth-connector.js";
import { deriveJwtSecret } from "../transport/oauth-helpers.js";
import { escapeHtml } from "../transport/oauth-connector.js";
import { createLogger, type Logger } from "../logging/logger.js";
import { createSupabaseRest, type SupabaseRest } from "../storage/supabase-rest.js";
import {
  createSupabaseAuthCodeStore,
  createSupabaseTokenRepository,
  createSupabaseUsedJtiStore,
  createSupabaseWhoopStateStore,
} from "../storage/supabase-stores.js";
import { deriveEncryptionKey } from "../storage/token-crypto.js";
import type { HostedConfig } from "./config.js";
import { createWhoopSession } from "./whoop-session.js";
import {
  WHOOP_CALLBACK_PATH,
  WHOOP_CONNECT_PATH,
  createWhoopLinkHandlers,
  type NodeHandler,
} from "./whoop-link.js";

export interface VercelHandlerDeps {
  config: HostedConfig;
  /** Injectable for tests; defaults to a fetch-based Supabase client. */
  db?: SupabaseRest;
  logger?: Logger;
}

const OAUTH_PATHS = new Set(["/authorize", "/token", "/register", "/revoke"]);

/** Minimal privacy notice — WHOOP requires a policy URL for every developer app. */
function privacyPage(): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Privacy Policy</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f7f7f8;
    color: #111; margin: 0; padding: 40px 16px; }
  main { max-width: 640px; margin: 0 auto; background: #fff; border-radius: 12px; padding: 32px; }
  h1 { font-size: 20px; margin: 0 0 12px; } h2 { font-size: 15px; margin: 20px 0 6px; }
  p, li { color: #444; font-size: 14px; line-height: 1.6; }
  @media (prefers-color-scheme: dark) { body { background: #111; color: #eee; }
    main { background: #1c1c1e; } p, li { color: #bbb; } }
</style></head>
<body><main>
  <h1>Privacy Policy</h1>
  <p>This is a private, single-user integration operated by its owner for personal use.
     It is not offered to the public, and no other users can sign up or connect.</p>
  <h2>Data accessed</h2>
  <p>With the owner's authorization, the server reads WHOOP profile, body measurement,
     cycle, recovery, sleep and workout data through the official WHOOP API. Access is read-only.</p>
  <h2>Use and sharing</h2>
  <p>Data is fetched on demand only to answer the owner's own requests in their AI assistant.
     It is not sold, shared with third parties, or used for advertising or analytics.</p>
  <h2>Storage</h2>
  <p>Only the WHOOP OAuth tokens are stored, encrypted, in a private database. WHOOP health
     data is not persisted beyond short-lived in-memory caching.</p>
  <h2>Revocation</h2>
  <p>Access can be revoked at any time in the WHOOP app or by deleting the stored tokens.</p>
</main></body></html>`;
}

function landingPage(publicUrl: string): string {
  const mcpUrl = `${publicUrl}/mcp`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WHOOP MCP Server</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f7f7f8;
    color: #111; margin: 0; padding: 40px 16px; }
  main { max-width: 560px; margin: 0 auto; background: #fff; border-radius: 12px; padding: 32px; }
  h1 { font-size: 20px; margin: 0 0 12px; } p, li { color: #444; font-size: 14px; line-height: 1.6; }
  code { background: #f1f1f3; padding: 2px 6px; border-radius: 4px; word-break: break-all; }
  @media (prefers-color-scheme: dark) { body { background: #111; color: #eee; }
    main { background: #1c1c1e; } p, li { color: #bbb; } code { background: #2c2c2e; } a { color: #8ab4ff; } }
</style></head>
<body><main>
  <h1>WHOOP MCP Server</h1>
  <ol>
    <li><a href="${WHOOP_CONNECT_PATH}">Connect your WHOOP account</a></li>
    <li>Add a custom connector in Claude with the URL <code>${escapeHtml(mcpUrl)}</code></li>
  </ol>
</main></body></html>`;
}

/**
 * Build the hosted request handler. Async because key derivation is async;
 * call once per cold start and reuse the returned handler.
 */
export async function createVercelHandler(deps: VercelHandlerDeps): Promise<NodeHandler> {
  const { config } = deps;
  const logger = deps.logger ?? createLogger({ level: config.logLevel, format: "json" });
  const db =
    deps.db ??
    createSupabaseRest({ url: config.supabaseUrl, serviceKey: config.supabaseServiceKey });

  const encryptionKey = await deriveEncryptionKey(config.tokenEncryptionSecret);
  const tokens = createSupabaseTokenRepository(db, encryptionKey);
  const connectUrl = `${config.publicUrl}${WHOOP_CONNECT_PATH}`;
  const resourceUrl = `${config.publicUrl}/mcp`;
  const resourceMetadataUrl = `${config.publicUrl}/.well-known/oauth-protected-resource/mcp`;

  const link = createWhoopLinkHandlers({
    publicUrl: config.publicUrl,
    connectorPassword: config.connectorPassword,
    whoopClientId: config.whoopClientId,
    whoopClientSecret: config.whoopClientSecret,
    tokens,
    states: createSupabaseWhoopStateStore(db),
    logger,
  });

  const jwtSecret = config.jwtSecret
    ? Buffer.from(config.jwtSecret, "utf-8")
    : await deriveJwtSecret(config.authToken);
  const oauthApp = createOAuthApp({
    connectorPassword: config.connectorPassword,
    publicUrl: config.publicUrl,
    allowedRedirectUris: config.allowedRedirectUris,
    jwtSecret,
    scopes: ["mcp"],
    client: {
      clientId: config.oauthClientId,
      clientName: "WHOOP MCP Connector",
      redirectUris: config.allowedRedirectUris,
    },
    // Vercel terminates TLS one hop in front of the function.
    trustProxy: 1,
    resourceServerUrl: resourceUrl,
    authCodeStore: createSupabaseAuthCodeStore(db),
    usedJtiStore: createSupabaseUsedJtiStore(db),
  });
  const oauthHandler = oauthApp.app as unknown as (
    req: IncomingMessage,
    res: ServerResponse
  ) => void;

  // Per-instance response cache; single-user, so keys need no identity.
  const cache = new MemoryCache();

  async function authenticate(token: string): Promise<AuthInfo | null> {
    if (safeTokenCompare(token, config.authToken)) {
      return { token, clientId: "static", scopes: ["mcp"] };
    }
    try {
      return await oauthApp.provider.verifyAccessToken(token);
    } catch {
      return null;
    }
  }

  function createRequestClient(): WhoopClient {
    const session = createWhoopSession({
      repository: tokens,
      oauthConfig: { clientId: config.whoopClientId, clientSecret: config.whoopClientSecret },
      connectUrl,
    });
    let clientPromise: Promise<WhoopClient> | undefined;
    return {
      async get<T>(path: string, options?: WhoopGetOptions): Promise<T> {
        clientPromise ??= session.getAccessToken().then((accessToken) =>
          createWhoopClient({
            accessToken,
            onTokenRefresh: async () => {
              const fresh = await session.refresh();
              cache.clear();
              return fresh;
            },
            logger,
            cache,
          })
        );
        return (await clientPromise).get<T>(path, options);
      },
    };
  }

  async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const token = extractBearerToken(req);
    const authInfo = token ? await authenticate(token) : null;
    if (!authInfo) {
      res.setHeader("WWW-Authenticate", `Bearer resource_metadata="${resourceMetadataUrl}"`);
      sendJson(res, 401, { error: "Unauthorized" });
      return;
    }

    if (req.method !== "POST") {
      // Stateless mode: no standalone SSE stream and no sessions to delete.
      res.setHeader("Allow", "POST");
      sendJson(res, 405, {
        jsonrpc: "2.0",
        error: { code: -32000, message: "Method not allowed. Use POST." },
        id: null,
      });
      return;
    }

    let body: unknown;
    try {
      body = JSON.parse(await readBody(req)) as unknown;
    } catch {
      sendJson(res, 400, { error: "Bad Request", message: "Invalid JSON body" });
      return;
    }

    (req as IncomingMessage & { auth?: AuthInfo }).auth = authInfo;
    const { server } = createWhoopServer(createRequestClient(), {
      privacyMode: config.privacyMode,
      disableResources: config.disableResources,
    });
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    res.on("close", () => {
      void transport.close();
      void server.close();
    });

    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (error) {
      logger.error("mcp request failed", {
        error: error instanceof Error ? error.message : String(error),
      });
      if (!res.headersSent) {
        sendJson(res, 500, {
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        });
      }
    }
  }

  return async (req, res) => {
    let url: URL;
    try {
      url = new URL(req.url ?? "/", config.publicUrl);
    } catch {
      sendJson(res, 400, { error: "Bad Request" });
      return;
    }
    const pathname = url.pathname;

    if (handleCors(req, res, config.allowedOrigins)) return;

    try {
      if (pathname === "/mcp") return await handleMcp(req, res);

      if (OAUTH_PATHS.has(pathname) || pathname.startsWith("/.well-known/")) {
        oauthHandler(req, res);
        return;
      }

      if (pathname === WHOOP_CONNECT_PATH) return await link.connect(req, res);
      if (pathname === WHOOP_CALLBACK_PATH) return await link.callback(req, res);

      if (pathname === "/health") {
        const bearer = extractBearerToken(req);
        if (bearer && safeTokenCompare(bearer, config.authToken)) {
          const stored = await tokens.load();
          sendJson(res, 200, { status: "ok", whoopConnected: stored !== null });
        } else {
          sendJson(res, 200, { status: "ok" });
        }
        return;
      }

      if (pathname === "/privacy" && (req.method === "GET" || req.method === "HEAD")) {
        res.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "public, max-age=3600",
        });
        res.end(privacyPage());
        return;
      }

      if (pathname === "/" && (req.method === "GET" || req.method === "HEAD")) {
        res.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store",
          "X-Frame-Options": "DENY",
        });
        res.end(landingPage(config.publicUrl));
        return;
      }

      sendJson(res, 404, { error: "Not Found" });
    } catch (error) {
      logger.error("request failed", {
        path: pathname,
        error: error instanceof Error ? error.message : String(error),
      });
      if (!res.headersSent) sendJson(res, 500, { error: "Internal Server Error" });
    }
  };
}
