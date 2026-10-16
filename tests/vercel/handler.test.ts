/**
 * End-to-end tests for the hosted (Vercel) handler: real HTTP server, fake
 * Supabase, mocked WHOOP API. Never touches the network.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from "vitest";
import { createServer, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { createHash, randomBytes } from "node:crypto";
import { createVercelHandler } from "../../src/vercel/handler.js";
import { parseHostedConfig } from "../../src/vercel/config.js";
import { createSupabaseTokenRepository } from "../../src/storage/supabase-stores.js";
import { deriveEncryptionKey } from "../../src/storage/token-crypto.js";
import type { Logger } from "../../src/logging/logger.js";
import { createFakeSupabase, type FakeSupabase } from "../helpers/fake-supabase.js";

const PUBLIC_URL = "https://whoop.example.com";
const AUTH_TOKEN = "t".repeat(48);
const PASSWORD = "correct horse battery staple";
const CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback";

const ENV = {
  WHOOP_CLIENT_ID: "whoop-client",
  WHOOP_CLIENT_SECRET: "whoop-secret",
  SUPABASE_URL: "https://proj.supabase.co",
  SUPABASE_SERVICE_ROLE_KEY: "sb_secret_test",
  MCP_AUTH_TOKEN: AUTH_TOKEN,
  MCP_CONNECTOR_PASSWORD: PASSWORD,
  PUBLIC_URL,
};

const silentLogger: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

const realFetch = globalThis.fetch;
let whoopFetch: ReturnType<typeof vi.fn>;
let db: FakeSupabase;
let server: Server;
let baseUrl: string;

function profileResponse(): Response {
  return new Response(
    JSON.stringify({ user_id: 42, email: "a@b.c", first_name: "Ada", last_name: "L" }),
    { status: 200, headers: { "Content-Type": "application/json" } }
  );
}

function tokenResponse(): Response {
  return new Response(
    JSON.stringify({
      access_token: "whoop-access",
      refresh_token: "whoop-refresh",
      expires_in: 3600,
      token_type: "Bearer",
      scope: "offline read:profile",
    }),
    { status: 200 }
  );
}

/**
 * Mimic @vercel/node's response helpers: Vercel assigns these as own
 * properties, shadowing Express's methods. Its redirect defaults to 307.
 */
function addVercelHelpers(res: ServerResponse): void {
  const helpers = res as ServerResponse & Record<string, unknown>;
  helpers.status = (code: number): ServerResponse => {
    res.statusCode = code;
    return res;
  };
  helpers.send = (body: string): ServerResponse => res.end(body);
  helpers.json = (body: unknown): ServerResponse => {
    res.setHeader("Content-Type", "application/json");
    return res.end(JSON.stringify(body));
  };
  helpers.redirect = (statusOrUrl: number | string, url?: string): ServerResponse => {
    const status = typeof statusOrUrl === "number" ? statusOrUrl : 307;
    res.writeHead(status, { Location: typeof statusOrUrl === "string" ? statusOrUrl : url });
    return res.end();
  };
}

beforeAll(async () => {
  db = createFakeSupabase();
  const handler = await createVercelHandler({
    config: parseHostedConfig(ENV),
    db,
    logger: silentLogger,
  });
  server = createServer((req, res) => {
    addVercelHelpers(res);
    void handler(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  whoopFetch = vi.fn();
  vi.stubGlobal("fetch", (input: string | URL | Request, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url.startsWith("https://api.prod.whoop.com")) {
      return (whoopFetch as unknown as typeof fetch)(input, init);
    }
    return realFetch(input, init);
  });
});

afterAll(async () => {
  vi.unstubAllGlobals();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  whoopFetch.mockReset();
  db.tables.clear();
});

async function mcp(body: unknown, token = AUTH_TOKEN): Promise<Response> {
  return realFetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    },
    body: JSON.stringify(body),
  });
}

const INITIALIZE = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "test", version: "1.0.0" },
  },
};

function callTool(name: string): unknown {
  return { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name, arguments: {} } };
}

async function storeWhoopTokens(): Promise<void> {
  const repo = createSupabaseTokenRepository(db, await deriveEncryptionKey(AUTH_TOKEN));
  await repo.save({
    access_token: "whoop-access",
    refresh_token: "whoop-refresh",
    expires_at: Date.now() + 3_600_000,
    token_type: "Bearer",
  });
}

describe("hosted handler — basic routes", () => {
  it("serves a landing page with the MCP URL", async () => {
    const res = await realFetch(`${baseUrl}/`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(`${PUBLIC_URL}/mcp`);
    expect(html).toContain("/whoop/connect");
  });

  it("reports health publicly and WHOOP link status with the bearer", async () => {
    expect(await (await realFetch(`${baseUrl}/health`)).json()).toEqual({ status: "ok" });
    const authed = await realFetch(`${baseUrl}/health`, {
      headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
    });
    expect(await authed.json()).toEqual({ status: "ok", whoopConnected: false });
  });

  it("serves a privacy policy page for the WHOOP developer app", async () => {
    const res = await realFetch(`${baseUrl}/privacy`);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("single-user");
  });

  it("returns 404 for unknown routes", async () => {
    expect((await realFetch(`${baseUrl}/nope`)).status).toBe(404);
  });
});

describe("hosted handler — /mcp", () => {
  it("rejects missing credentials with a resource_metadata challenge", async () => {
    const res = await mcp(INITIALIZE, "wrong");
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe(
      `Bearer resource_metadata="${PUBLIC_URL}/.well-known/oauth-protected-resource/mcp"`
    );
  });

  it("rejects GET (no SSE in stateless mode)", async () => {
    const res = await realFetch(`${baseUrl}/mcp`, {
      headers: { Authorization: `Bearer ${AUTH_TOKEN}` },
    });
    expect(res.status).toBe(405);
  });

  it("rejects invalid JSON", async () => {
    const res = await realFetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: { Authorization: `Bearer ${AUTH_TOKEN}`, "Content-Type": "application/json" },
      body: "{not json",
    });
    expect(res.status).toBe(400);
  });

  it("initializes statelessly with a JSON response", async () => {
    const res = await mcp(INITIALIZE);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(res.headers.get("mcp-session-id")).toBeNull();
    const json = (await res.json()) as { result: { serverInfo: { name: string } } };
    expect(json.result.serverInfo.name).toBe("whoop-mcp");
  });

  it("tells Claude where to connect WHOOP when no account is linked", async () => {
    const res = await mcp(callTool("get_profile"));
    const json = (await res.json()) as {
      result: { isError: boolean; content: Array<{ text: string }> };
    };
    expect(json.result.isError).toBe(true);
    expect(json.result.content[0]?.text).toContain(`${PUBLIC_URL}/whoop/connect`);
    expect(whoopFetch).not.toHaveBeenCalled();
  });

  it("calls WHOOP with the stored token", async () => {
    await storeWhoopTokens();
    whoopFetch.mockResolvedValue(profileResponse());

    const res = await mcp(callTool("get_profile"));
    const json = (await res.json()) as {
      result: { isError?: boolean; structuredContent: { user_id: number } };
    };
    expect(json.result.isError).toBeUndefined();
    expect(json.result.structuredContent.user_id).toBe(42);

    const [url, init] = whoopFetch.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toContain("/v2/user/profile/basic");
    expect(JSON.stringify(init.headers)).toContain("Bearer whoop-access");
  });
});

describe("hosted handler — WHOOP connect flow", () => {
  async function submitPassword(password: string): Promise<Response> {
    return realFetch(`${baseUrl}/whoop/connect`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ connector_password: password }).toString(),
      redirect: "manual",
    });
  }

  it("shows a password form", async () => {
    const res = await realFetch(`${baseUrl}/whoop/connect`);
    expect(res.status).toBe(200);
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(await res.text()).toContain('name="connector_password"');
  });

  it("rejects a wrong password", async () => {
    const res = await submitPassword("wrong password!!");
    expect(res.status).toBe(401);
    expect(db.rows("whoop_oauth_states")).toHaveLength(0);
  });

  it("links the account end to end and stores encrypted tokens", async () => {
    const res = await submitPassword(PASSWORD);
    expect(res.status).toBe(303);
    const location = new URL(res.headers.get("location") ?? "");
    expect(location.origin + location.pathname).toBe(
      "https://api.prod.whoop.com/oauth/oauth2/auth"
    );
    expect(location.searchParams.get("redirect_uri")).toBe(`${PUBLIC_URL}/whoop/callback`);
    expect(location.searchParams.get("code_challenge_method")).toBe("S256");
    const state = location.searchParams.get("state") ?? "";

    whoopFetch.mockResolvedValue(tokenResponse());
    const callback = await realFetch(
      `${baseUrl}/whoop/callback?code=whoop-code&state=${encodeURIComponent(state)}`
    );
    expect(callback.status).toBe(200);
    expect(await callback.text()).toContain("WHOOP connected");

    const body = String((whoopFetch.mock.calls[0] as [string, RequestInit])[1].body);
    expect(body).toContain("code=whoop-code");
    expect(body).toContain("code_verifier=");
    expect(body).toContain(encodeURIComponent(`${PUBLIC_URL}/whoop/callback`));

    const [row] = db.rows("whoop_tokens");
    expect(row?.access_token).not.toBe("whoop-access");

    // state is single-use
    const replay = await realFetch(`${baseUrl}/whoop/callback?code=x&state=${state}`);
    expect(replay.status).toBe(400);
  });

  it("rejects callbacks with an unknown state", async () => {
    const res = await realFetch(`${baseUrl}/whoop/callback?code=x&state=forged`);
    expect(res.status).toBe(400);
    expect(whoopFetch).not.toHaveBeenCalled();
  });

  it("shows WHOOP-side errors", async () => {
    const res = await realFetch(`${baseUrl}/whoop/callback?error=access_denied`);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("access_denied");
  });
});

describe("hosted handler — Claude OAuth connector", () => {
  it("publishes authorization server and protected resource metadata", async () => {
    const as = (await (
      await realFetch(`${baseUrl}/.well-known/oauth-authorization-server`)
    ).json()) as { issuer: string; token_endpoint: string };
    expect(as.issuer).toBe(`${PUBLIC_URL}/`);
    expect(as.token_endpoint).toBe(`${PUBLIC_URL}/token`);

    const prm = (await (
      await realFetch(`${baseUrl}/.well-known/oauth-protected-resource/mcp`)
    ).json()) as { resource: string };
    expect(prm.resource).toBe(`${PUBLIC_URL}/mcp`);
  });

  it("issues tokens via Supabase-backed codes that work on /mcp", async () => {
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");

    const authorize = await realFetch(`${baseUrl}/authorize`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "whoop-mcp-connector",
        redirect_uri: CLAUDE_CALLBACK,
        response_type: "code",
        state: "claude-state",
        code_challenge: challenge,
        code_challenge_method: "S256",
        connector_password: PASSWORD,
      }).toString(),
      redirect: "manual",
    });
    // 302 (not Vercel's default 307) so the browser follows with GET instead
    // of re-POSTing the password form to Claude's callback.
    expect(authorize.status).toBe(302);
    const redirect = new URL(authorize.headers.get("location") ?? "");
    const code = redirect.searchParams.get("code") ?? "";
    expect(redirect.searchParams.get("state")).toBe("claude-state");
    expect(db.rows("oauth_auth_codes")).toHaveLength(1);

    const tokenRes = await realFetch(`${baseUrl}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        code_verifier: verifier,
        client_id: "whoop-mcp-connector",
        redirect_uri: CLAUDE_CALLBACK,
      }).toString(),
    });
    expect(tokenRes.status).toBe(200);
    const tokens = (await tokenRes.json()) as { access_token: string; refresh_token: string };

    const res = await mcp(INITIALIZE, tokens.access_token);
    expect(res.status).toBe(200);

    // Refresh-token rotation with replay detection persisted in Supabase
    const refresh = (token: string): Promise<Response> =>
      realFetch(`${baseUrl}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: token,
          client_id: "whoop-mcp-connector",
        }).toString(),
      });
    expect((await refresh(tokens.refresh_token)).status).toBe(200);
    // Replay is rejected (the SDK maps the provider's plain Error to 500 server_error)
    expect((await refresh(tokens.refresh_token)).status).not.toBe(200);
    expect(db.rows("oauth_used_jtis")).toHaveLength(1);
  });
});
