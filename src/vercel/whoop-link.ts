/**
 * Browser flow that links a WHOOP account to the hosted server.
 *
 *   GET  /whoop/connect   — password form (connector password)
 *   POST /whoop/connect   — verify password → redirect to WHOOP consent
 *   GET  /whoop/callback  — verify state → exchange code → store tokens
 *
 * Replaces the local loopback callback server used by the stdio CLI. The
 * redirect URI `<PUBLIC_URL>/whoop/callback` must be registered in the WHOOP
 * developer dashboard.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import {
  buildAuthorizationUrl,
  exchangeCodeForTokens,
  toOAuthTokens,
  type OAuthConfig,
} from "../auth/oauth.js";
import { readBody, safeTokenCompare } from "../transport/http.js";
import { escapeHtml } from "../transport/oauth-connector.js";
import type { WhoopStateStore, WhoopTokenRepository } from "../storage/supabase-stores.js";
import type { Logger } from "../logging/logger.js";

export const WHOOP_CONNECT_PATH = "/whoop/connect";
export const WHOOP_CALLBACK_PATH = "/whoop/callback";

/** Failed password attempts allowed per IP per minute (per instance). */
const MAX_ATTEMPTS_PER_MINUTE = 5;

export interface WhoopLinkOptions {
  publicUrl: string;
  connectorPassword: string;
  whoopClientId: string;
  whoopClientSecret: string;
  tokens: WhoopTokenRepository;
  states: WhoopStateStore;
  logger?: Logger;
}

export type NodeHandler = (req: IncomingMessage, res: ServerResponse) => Promise<void>;

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

function sendPage(res: ServerResponse, status: number, title: string, body: string): void {
  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f7f7f8; margin: 0; display: flex; align-items: center;
      justify-content: center; min-height: 100vh; padding: 20px; color: #111; }
    .card { background: #fff; border-radius: 12px; padding: 32px; max-width: 420px;
      width: 100%; box-shadow: 0 1px 3px rgba(0,0,0,.06), 0 8px 24px rgba(0,0,0,.04); }
    h1 { font-size: 18px; margin: 0 0 8px 0; }
    p { color: #555; font-size: 14px; line-height: 1.5; margin: 0 0 16px 0; }
    code { background: #f1f1f3; padding: 2px 6px; border-radius: 4px; font-size: 13px; word-break: break-all; }
    .error { color: #c00; }
    label { display: block; font-size: 13px; font-weight: 500; margin-bottom: 6px; }
    input[type=password] { width: 100%; padding: 10px 12px; border: 1px solid #ddd;
      border-radius: 6px; font-size: 14px; box-sizing: border-box; }
    button { margin-top: 16px; width: 100%; padding: 10px; border: 0; border-radius: 6px;
      background: #111; color: #fff; font-size: 14px; font-weight: 500; cursor: pointer; }
    @media (prefers-color-scheme: dark) {
      body { background: #111; color: #eee; } .card { background: #1c1c1e; }
      p { color: #aaa; } code { background: #2c2c2e; } input[type=password] { background: #111; color: #eee; border-color: #333; }
      button { background: #eee; color: #111; }
    }
  </style>
</head>
<body>
  <div class="card">
    ${body}
  </div>
</body>
</html>`;
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy":
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https:; frame-ancestors 'none'; base-uri 'none'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(html);
}

function connectForm(error?: string): string {
  return `<h1>Connect your WHOOP account</h1>
    <p>Enter the connector password to link a WHOOP account to this MCP server.
       Any previously linked account is replaced.</p>
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
    <form method="POST" action="${WHOOP_CONNECT_PATH}" autocomplete="off">
      <label for="connector_password">Connector password</label>
      <input id="connector_password" name="connector_password" type="password" required autofocus>
      <button type="submit">Continue to WHOOP</button>
    </form>`;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

export function clientIp(req: IncomingMessage): string {
  const xff = req.headers["x-forwarded-for"];
  const first = typeof xff === "string" ? xff.split(",")[0]?.trim() : undefined;
  return first || req.socket.remoteAddress || "unknown";
}

export function createWhoopLinkHandlers(options: WhoopLinkOptions): {
  connect: NodeHandler;
  callback: NodeHandler;
} {
  const redirectUri = `${options.publicUrl}${WHOOP_CALLBACK_PATH}`;
  const oauthConfig: OAuthConfig = {
    clientId: options.whoopClientId,
    clientSecret: options.whoopClientSecret,
    redirectUri,
  };
  const attempts = new Map<string, { count: number; resetAt: number }>();

  function tooManyAttempts(ip: string): boolean {
    const now = Date.now();
    const bucket = attempts.get(ip);
    if (!bucket || bucket.resetAt <= now) {
      attempts.set(ip, { count: 0, resetAt: now + 60_000 });
      return false;
    }
    return bucket.count >= MAX_ATTEMPTS_PER_MINUTE;
  }

  function recordFailure(ip: string): void {
    const bucket = attempts.get(ip);
    if (bucket) bucket.count++;
  }

  const connect: NodeHandler = async (req, res) => {
    if (req.method === "GET") {
      sendPage(res, 200, "Connect WHOOP", connectForm());
      return;
    }
    if (req.method !== "POST") {
      res.writeHead(405, { Allow: "GET, POST" });
      res.end();
      return;
    }

    const ip = clientIp(req);
    if (tooManyAttempts(ip)) {
      sendPage(
        res,
        429,
        "Connect WHOOP",
        connectForm("Too many attempts. Wait a minute and retry.")
      );
      return;
    }

    let password = "";
    try {
      password = new URLSearchParams(await readBody(req)).get("connector_password") ?? "";
    } catch {
      sendPage(res, 400, "Connect WHOOP", connectForm("Invalid form submission."));
      return;
    }
    if (!safeTokenCompare(password, options.connectorPassword)) {
      recordFailure(ip);
      sendPage(res, 401, "Connect WHOOP", connectForm("Incorrect password. Try again."));
      return;
    }

    const state = randomBytes(24).toString("base64url");
    const codeVerifier = randomBytes(32).toString("base64url");
    const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
    await options.states.create(state, codeVerifier);

    res.writeHead(303, {
      Location: buildAuthorizationUrl(oauthConfig, state, codeChallenge),
      "Cache-Control": "no-store",
    });
    res.end();
  };

  const callback: NodeHandler = async (req, res) => {
    const url = new URL(req.url ?? "/", options.publicUrl);
    const retry = `<p><a href="${WHOOP_CONNECT_PATH}">Start again</a></p>`;

    const whoopError = url.searchParams.get("error");
    if (whoopError) {
      sendPage(
        res,
        400,
        "WHOOP connection failed",
        `<h1>WHOOP connection failed</h1><p class="error">WHOOP returned: ${escapeHtml(whoopError)}</p>${retry}`
      );
      return;
    }

    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const codeVerifier = state ? await options.states.consume(state) : null;
    if (!code || !codeVerifier) {
      sendPage(
        res,
        400,
        "WHOOP connection failed",
        `<h1>Link expired or invalid</h1><p>This connection attempt is no longer valid.</p>${retry}`
      );
      return;
    }

    try {
      const response = await exchangeCodeForTokens(code, oauthConfig, codeVerifier);
      await options.tokens.save(toOAuthTokens(response));
    } catch (error) {
      options.logger?.error("whoop connect failed", {
        error: error instanceof Error ? error.message : String(error),
      });
      sendPage(
        res,
        502,
        "WHOOP connection failed",
        `<h1>WHOOP connection failed</h1><p>The authorization code could not be exchanged. Check WHOOP_CLIENT_ID, WHOOP_CLIENT_SECRET and that <code>${escapeHtml(redirectUri)}</code> is registered as a redirect URI.</p>${retry}`
      );
      return;
    }

    options.logger?.info("whoop account connected");
    sendPage(
      res,
      200,
      "WHOOP connected",
      `<h1>WHOOP connected ✓</h1>
       <p>Your WHOOP account is linked. Add this MCP server URL to Claude:</p>
       <p><code>${escapeHtml(options.publicUrl)}/mcp</code></p>
       <p>You can close this tab.</p>`
    );
  };

  return { connect, callback };
}
