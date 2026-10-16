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
import type { LoginGuard } from "../transport/oauth-helpers.js";
import type { Logger } from "../logging/logger.js";

export const WHOOP_CONNECT_PATH = "/whoop/connect";
export const WHOOP_CALLBACK_PATH = "/whoop/callback";

/** The connect form only carries a password. */
const MAX_FORM_BYTES = 4 * 1024;

/** `__Host-` prefix: Secure, host-only, Path=/ — cannot be set by subdomains. */
export const STATE_COOKIE = "__Host-whoop_link_state";
const STATE_COOKIE_MAX_AGE = 10 * 60;

function readCookie(req: IncomingMessage, name: string): string | null {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const eq = part.indexOf("=");
    if (eq !== -1 && part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

export interface WhoopLinkOptions {
  publicUrl: string;
  connectorPassword: string;
  whoopClientId: string;
  whoopClientSecret: string;
  tokens: WhoopTokenRepository;
  states: WhoopStateStore;
  /** Shared with /authorize so guesses on both endpoints count together. */
  loginGuard: LoginGuard;
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

    if (await options.loginGuard.isLocked()) {
      sendPage(
        res,
        429,
        "Connect WHOOP",
        connectForm("Too many failed attempts. Try again in 15 minutes.")
      );
      return;
    }

    let password = "";
    try {
      const form = new URLSearchParams(await readBody(req, MAX_FORM_BYTES));
      password = form.get("connector_password") ?? "";
    } catch {
      sendPage(res, 400, "Connect WHOOP", connectForm("Invalid form submission."));
      return;
    }
    if (!safeTokenCompare(password, options.connectorPassword)) {
      await options.loginGuard.recordFailure("whoop-connect", clientIp(req));
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
      // Binds the flow to this browser: a leaked WHOOP consent URL cannot be
      // completed elsewhere to swap in another WHOOP account.
      "Set-Cookie": `${STATE_COOKIE}=${state}; Path=/; Max-Age=${STATE_COOKIE_MAX_AGE}; HttpOnly; Secure; SameSite=Lax`,
    });
    res.end();
  };

  const callback: NodeHandler = async (req, res) => {
    const url = new URL(req.url ?? "/", options.publicUrl);
    const retry = `<p><a href="${WHOOP_CONNECT_PATH}">Start again</a></p>`;
    // The state cookie is single-use: clear it on every callback outcome.
    res.setHeader(
      "Set-Cookie",
      `${STATE_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`
    );

    const whoopError = url.searchParams.get("error");
    if (whoopError) {
      // Fixed messages only — never reflect attacker-chosen text on this origin.
      const message =
        whoopError === "access_denied"
          ? "You declined access on WHOOP."
          : "WHOOP reported an error while authorizing.";
      sendPage(
        res,
        400,
        "WHOOP connection failed",
        `<h1>WHOOP connection failed</h1><p class="error">${message}</p>${retry}`
      );
      return;
    }

    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const cookieState = readCookie(req, STATE_COOKIE);
    const browserMatches =
      state !== null && cookieState !== null && safeTokenCompare(state, cookieState);
    const codeVerifier = browserMatches && state ? await options.states.consume(state) : null;
    if (!code || !codeVerifier) {
      sendPage(
        res,
        400,
        "WHOOP connection failed",
        `<h1>Link expired or invalid</h1><p>This connection attempt is no longer valid. Start it again and finish it in the same browser within 10 minutes.</p>${retry}`
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
