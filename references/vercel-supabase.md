# Deploy on Vercel with Supabase

Run the WHOOP MCP server as a serverless function on Vercel, with all state
in a Supabase Postgres database. Claude (web, desktop, mobile) connects to it
as a custom connector over OAuth; header-based clients (Claude Code, Cursor)
can use a static bearer token.

This is a **single-user** deployment: one server links one WHOOP account.

## How it differs from the Docker / long-running server

| Concern | Docker / `MCP_TRANSPORT=http` | Vercel |
|---|---|---|
| WHOOP tokens | `~/.whoop-mcp/tokens.json` | `whoop_tokens` table, AES-256-GCM encrypted |
| WHOOP authorization | Local browser + loopback callback | `https://<your-domain>/whoop/connect` |
| Connector auth codes / refresh-token replay list | In memory | `oauth_auth_codes` / `oauth_used_jtis` tables |
| MCP transport | Stateful Streamable HTTP with SSE | Stateless Streamable HTTP, JSON responses (POST only) |
| Token refresh | In process | Single-flight across instances via a lease row |

## Routes

| Route | Purpose |
|---|---|
| `GET /` | Landing page with setup links |
| `GET/POST /whoop/connect` | Password-protected page that links your WHOOP account |
| `GET /whoop/callback` | WHOOP OAuth redirect target |
| `POST /mcp` | MCP endpoint |
| `/authorize`, `/token`, `/.well-known/*` | OAuth 2.1 connector for Claude |
| `GET /health` | Liveness; with the bearer token also reports `whoopConnected` |

## 1. Create the Supabase project

1. Create a project at [supabase.com](https://supabase.com/dashboard).
2. Open **SQL Editor** and run
   [`supabase/migrations/20261016000000_whoop_mcp_init.sql`](../supabase/migrations/20261016000000_whoop_mcp_init.sql),
   or with the Supabase CLI: `supabase link --project-ref <ref> && supabase db push`.
3. From **Project Settings → API**, copy the project URL and the
   **service-role / secret key**. That key bypasses Row Level Security, so it
   must only ever live in Vercel's server-side environment variables.

All tables have RLS enabled with no policies, so the anon / publishable key
cannot read them.

## 2. Register the WHOOP redirect URI

In the [WHOOP developer dashboard](https://developer-dashboard.whoop.com),
add this redirect URI to your app:

```text
https://<your-domain>/whoop/callback
```

`<your-domain>` is your Vercel production domain (for example
`whoop-mcp.vercel.app`) or a custom domain. It must match `PUBLIC_URL`
exactly.

## 3. Deploy to Vercel

Import the repository in Vercel (framework preset **Other**); `vercel.json`
configures the build. Then set these environment variables for
**Production**:

| Variable | Required | Notes |
|---|---|---|
| `WHOOP_CLIENT_ID` | yes | From the WHOOP developer dashboard |
| `WHOOP_CLIENT_SECRET` | yes | From the WHOOP developer dashboard |
| `SUPABASE_URL` | yes | `https://<ref>.supabase.co` |
| `SUPABASE_SERVICE_ROLE_KEY` | yes | Or `SUPABASE_SECRET_KEY` (`sb_secret_...`) |
| `MCP_AUTH_TOKEN` | yes | ≥ 32 chars. Static bearer for header clients (Claude Code, Cursor) |
| `MCP_JWT_SECRET` | yes | ≥ 32 chars, different from the others. Signs connector tokens |
| `WHOOP_TOKEN_ENCRYPTION_KEY` | yes | ≥ 32 chars, different from the others. Encrypts WHOOP tokens at rest |
| `MCP_CONNECTOR_PASSWORD` | yes | ≥ 12 chars. Asked when Claude connects and on `/whoop/connect` |
| `PUBLIC_URL` | no | Defaults to `https://$VERCEL_PROJECT_PRODUCTION_URL`. Set it when you use a custom domain |
| `ALLOWED_REDIRECT_URIS` | no | Defaults to Claude's callbacks (`https://claude.ai/api/mcp/auth_callback`, `https://claude.com/api/mcp/auth_callback`) |
| `MCP_OAUTH_CLIENT_ID` | no | Defaults to `whoop-mcp-connector` |
| `WHOOP_MCP_PRIVACY_MODE` | no | `standard` (default) or `aggregate` |

With the Vercel CLI:

```bash
vercel link
vercel env add WHOOP_CLIENT_ID production
# …repeat for each variable…
vercel deploy --prod
```

If you use Vercel's Supabase integration, `SUPABASE_URL` and
`SUPABASE_SERVICE_ROLE_KEY` are set for you.

Generate each secret separately, e.g. `openssl rand -hex 32 | pbcopy`. Use a
long random connector password (20+ characters from a password manager).

| Rotate | Effect |
|---|---|
| `MCP_AUTH_TOKEN` | Header clients need the new value; nothing else changes |
| `MCP_JWT_SECRET` | Signs Claude out everywhere (use this to revoke connector access) |
| `WHOOP_TOKEN_ENCRYPTION_KEY` | Stored WHOOP tokens become unreadable; reconnect at `/whoop/connect` |

Scope every variable to **Production** only, and keep Vercel's *Git Fork
Protection* enabled so pull requests from forks never run with these secrets.

## 4. Link your WHOOP account

Open `https://<your-domain>/whoop/connect`, enter the connector password and
approve access on WHOOP. When the page says **WHOOP connected**, the tokens are
stored and refreshed automatically from then on.

If WHOOP access is revoked or expires, tools answer with a message that points
back to this page.

## 5. Connect Claude

**claude.ai / Claude Desktop / mobile:** Settings → Connectors → Add custom
connector:

- URL: `https://<your-domain>/mcp`
- Advanced settings → OAuth Client ID: `whoop-mcp-connector` (or your
  `MCP_OAUTH_CLIENT_ID`)

Claude opens the authorization page; enter the connector password.

**Claude Code:**

```bash
claude mcp add --transport http whoop https://<your-domain>/mcp \
  --header "Authorization: Bearer $MCP_AUTH_TOKEN"
```

## Verify

```bash
curl https://<your-domain>/health
curl -H "Authorization: Bearer $MCP_AUTH_TOKEN" https://<your-domain>/health
# → {"status":"ok","whoopConnected":true}
```

## Security model

- `/mcp` accepts either the static bearer or a connector access token
  (HS256 JWT, 1 hour). Refresh tokens rotate and replays are rejected.
- The connector password gates both `/authorize` and `/whoop/connect`.
  After 10 failed attempts within 15 minutes (counted in Supabase across all
  instances and both forms) both are locked for everyone until the window passes.
- The WHOOP connect flow is bound to the browser that started it
  (`__Host-` cookie), so a leaked WHOOP consent URL cannot be completed elsewhere.
- WHOOP tokens are AES-256-GCM encrypted; login codes and states are stored as
  SHA-256 hashes. All tables have RLS with no policies and no anon grants.
- Pages send a strict CSP, `X-Frame-Options: DENY`, `nosniff` and
  `no-referrer`. Configuration errors only name variables in the deployment logs.

## Limits

- **Single user.** Linking another WHOOP account replaces the current one.
- **No server push.** The stateless transport answers `POST /mcp` only;
  `GET` (SSE) returns 405, which MCP clients handle.
- **Function duration.** `vercel.json` sets `maxDuration` to 60 s; multi-week
  analytics tools make several WHOOP calls. Raise it if your plan allows.
- **Rate limits** for password attempts are per function instance.
