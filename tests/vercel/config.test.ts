import { describe, it, expect } from "vitest";
import { DEFAULT_ALLOWED_REDIRECT_URIS, parseHostedConfig } from "../../src/vercel/config.js";

const BASE = {
  WHOOP_CLIENT_ID: "client-id",
  WHOOP_CLIENT_SECRET: "client-secret",
  SUPABASE_URL: "https://proj.supabase.co",
  SUPABASE_SERVICE_ROLE_KEY: "sb_secret_x",
  MCP_AUTH_TOKEN: "a".repeat(64),
  MCP_JWT_SECRET: "j".repeat(64),
  WHOOP_TOKEN_ENCRYPTION_KEY: "e".repeat(64),
  MCP_CONNECTOR_PASSWORD: "correct horse battery",
  PUBLIC_URL: "https://whoop.example.com/",
};

describe("parseHostedConfig", () => {
  it("parses a complete configuration with defaults", () => {
    const config = parseHostedConfig(BASE);
    expect(config.publicUrl).toBe("https://whoop.example.com");
    expect(config.allowedRedirectUris).toEqual(DEFAULT_ALLOWED_REDIRECT_URIS);
    expect(config.oauthClientId).toBe("whoop-mcp-connector");
    expect(config.jwtSecret).toBe(BASE.MCP_JWT_SECRET);
    expect(config.tokenEncryptionSecret).toBe(BASE.WHOOP_TOKEN_ENCRYPTION_KEY);
    expect(config.privacyMode).toBe("standard");
  });

  it("infers PUBLIC_URL from Vercel's production URL", () => {
    const config = parseHostedConfig({
      ...BASE,
      PUBLIC_URL: undefined,
      VERCEL_PROJECT_PRODUCTION_URL: "whoop.vercel.app",
    });
    expect(config.publicUrl).toBe("https://whoop.vercel.app");
  });

  it("accepts SUPABASE_SECRET_KEY as an alternative", () => {
    const env = {
      ...BASE,
      SUPABASE_SERVICE_ROLE_KEY: undefined,
      SUPABASE_SECRET_KEY: "sb_secret_y",
    };
    expect(parseHostedConfig(env).supabaseServiceKey).toBe("sb_secret_y");
  });

  it("honours explicit overrides", () => {
    const config = parseHostedConfig({
      ...BASE,
      ALLOWED_REDIRECT_URIS: "https://a.example/cb, https://b.example/cb",

      WHOOP_MCP_PRIVACY_MODE: "aggregate",
      WHOOP_MCP_DISABLE_RESOURCES: "1",
      MCP_ALLOWED_ORIGINS: "https://x.example",
    });
    expect(config.allowedRedirectUris).toEqual(["https://a.example/cb", "https://b.example/cb"]);
    expect(config.privacyMode).toBe("aggregate");
    expect(config.disableResources).toBe(true);
    expect(config.allowedOrigins).toEqual(["https://x.example"]);
  });

  it("reports every problem at once without leaking values", () => {
    let message = "";
    try {
      parseHostedConfig({
        MCP_AUTH_TOKEN: "short-secret-value",
        MCP_CONNECTOR_PASSWORD: "short",
        PUBLIC_URL: "http://insecure.example",
        SUPABASE_URL: "not a url",
      });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain("WHOOP_CLIENT_ID is required.");
    expect(message).toContain("WHOOP_CLIENT_SECRET is required.");
    expect(message).toContain("SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_SECRET_KEY) is required.");
    expect(message).toContain("MCP_AUTH_TOKEN must be at least 32 characters.");
    expect(message).toContain("MCP_CONNECTOR_PASSWORD must be at least 12 characters.");
    expect(message).toContain("PUBLIC_URL must use https://");
    expect(message).toContain("SUPABASE_URL is not a valid URL.");
    expect(message).not.toContain("short-secret-value");
  });

  it("requires independent JWT and encryption secrets of at least 32 characters", () => {
    expect(() =>
      parseHostedConfig({
        ...BASE,
        MCP_JWT_SECRET: undefined,
        WHOOP_TOKEN_ENCRYPTION_KEY: undefined,
      })
    ).toThrow(/MCP_JWT_SECRET is required[\s\S]*WHOOP_TOKEN_ENCRYPTION_KEY is required/);
    expect(() => parseHostedConfig({ ...BASE, MCP_JWT_SECRET: "short" })).toThrow(
      "MCP_JWT_SECRET must be at least 32 characters."
    );
  });

  it("rejects reusing one secret for several purposes", () => {
    expect(() =>
      parseHostedConfig({ ...BASE, WHOOP_TOKEN_ENCRYPTION_KEY: BASE.MCP_AUTH_TOKEN })
    ).toThrow("must all be different");
  });

  it("requires a public URL when not on Vercel", () => {
    expect(() => parseHostedConfig({ ...BASE, PUBLIC_URL: undefined })).toThrow(
      "PUBLIC_URL is required"
    );
  });
});
