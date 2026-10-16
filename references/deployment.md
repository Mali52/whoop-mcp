# Docker and Remote Hosting

> Prefer serverless? See [Vercel + Supabase](vercel-supabase.md).

[Back to README](../README.md)

## Deployment (Docker + Cloud Hosting)

The HTTP transport (`MCP_TRANSPORT=http`) makes this server suitable for remote
hosting so that web/mobile MCP clients (e.g. claude.ai connectors) can connect
to your personal WHOOP data over the network. A multi-stage
[Dockerfile](../Dockerfile) is included.

> **Security warning.** When running over HTTP you are exposing your WHOOP data
> behind a single bearer token. Use a strong random `MCP_AUTH_TOKEN`
> (`openssl rand -hex 32`), only deploy behind TLS, restrict
> `MCP_ALLOWED_ORIGINS`, and treat the host as a personal-use deployment — not
> a multi-tenant service.

### Image characteristics

- Multi-stage build on `node:22-alpine`; image size varies with the base and dependencies.
- Runs as the unprivileged built-in `node` user (UID 1000).
- `tini` as PID 1 for clean signal forwarding (graceful shutdown).
- Health check uses Node's native `fetch` against `/health` — no `curl`/`wget`
  baked into the image.
- All configuration is supplied at runtime via env vars; no secrets are baked
  into image layers.

### Build & run locally

Authorize locally first with `setup --verify`, using the same WHOOP application.
Stop other servers using those tokens before moving the deployment to Docker.
The container cannot complete an unattended browser grant automatically. Its
`/home/node/.whoop-mcp` directory must be writable by UID 1000 and persisted;
on Linux, provision a private volume with the correct ownership before launch.
Do not bake tokens into the image or mount them read-only: refresh rewrites them.

Supply credentials and a strong, saved `MCP_AUTH_TOKEN` in a private env file
(POSIX permissions `0600`). Never commit it. The bind mount below reuses the
locally authorized token directory; verify ownership on your Docker platform.

```bash
docker build -t whoop-mcp .

# Smoke test (runs node, prints "ok", exits)
docker run --rm whoop-mcp node -e "console.log('ok')"

# Run the HTTP server on loopback; .env.http contains the required secrets
docker run --rm -p 127.0.0.1:3000:3000 \
  --env-file .env.http \
  --mount "type=bind,src=$HOME/.whoop-mcp,dst=/home/node/.whoop-mcp" \
  whoop-mcp

# Health check
curl http://localhost:3000/health
```

`/mcp` requires authentication. Public `/health` provides basic liveness. With
the static bearer token, it additionally probes WHOOP and returns uptime plus
`whoopApi: "ok" | "error"`; HTTP 200 alone does not mean that probe succeeded.
Health checks do not guarantee future credential validity. Remote clients cannot
reach the loopback example directly; publish only through an authenticated TLS host.

Required env vars (HTTP mode):

| Variable                | Required | Default      | Notes                                                       |
| ----------------------- | -------- | ------------ | ----------------------------------------------------------- |
| `MCP_TRANSPORT`         | no       | `http`       | Image default; override with `stdio` or `both` if needed.   |
| `MCP_AUTH_TOKEN`        | **yes**  | —            | Bearer token clients must send. Generate ≥32 random bytes.  |
| `WHOOP_CLIENT_ID`       | **yes**  | —            | From your WHOOP developer app.                              |
| `WHOOP_CLIENT_SECRET`   | **yes**  | —            | From your WHOOP developer app.                              |
| `MCP_PORT`              | no       | `3000`       | Listen port.                                                |
| `MCP_HOST`              | no       | `0.0.0.0`    | Listen interface.                                           |
| `MCP_ALLOWED_ORIGINS`   | no       | (none)       | Comma-separated CORS allowlist.                             |
| `MCP_TRUST_PROXY`       | no       | `0`          | Set `1` only when a trusted proxy controls forwarded headers. |
| `LOG_LEVEL`             | no       | `info`       | `debug`/`info`/`warn`/`error`.                              |
| `LOG_FORMAT`            | no       | `json`       | `json` for prod, `pretty` for local dev.                    |
| `MCP_CONNECTOR_PASSWORD`| no       | —            | If set (≥12 chars), enables the OAuth 2.1 connector for claude.ai web/mobile. Requires `PUBLIC_URL` + `ALLOWED_REDIRECT_URIS`. |
| `PUBLIC_URL`            | no       | —            | Public `https://` origin used as OAuth issuer.              |
| `ALLOWED_REDIRECT_URIS` | no       | —            | Comma-separated exact-match list of OAuth redirect URIs.    |
| `MCP_JWT_SECRET`        | no       | (HKDF)       | Override JWT signing key. Defaults to HKDF derivation from `MCP_AUTH_TOKEN`. |
| `MCP_OAUTH_CLIENT_ID`   | no       | `whoop-mcp-connector` | OAuth client identifier advertised by the connector. |

### Fly.io

[Fly.io](https://fly.io) can build the Dockerfile and terminate TLS. Hosting and
volume charges depend on your account; this is not a free-hosting guarantee.
Provision persistent storage at `/home/node/.whoop-mcp`, securely transfer the
initial authorized tokens, and verify UID 1000 ownership before serving traffic.

```bash
# One-time: install flyctl, sign in, and create the app from this repo's Dockerfile
brew install flyctl
fly auth login
fly launch --no-deploy --copy-config --name whoop-mcp-<your-suffix>

# Set secrets (these are encrypted and injected as env at runtime — never baked in)
fly secrets set \
  MCP_AUTH_TOKEN="$(openssl rand -hex 32)" \
  WHOOP_CLIENT_ID="..." \
  WHOOP_CLIENT_SECRET="..." \
  MCP_TRUST_PROXY=1

# Deploy
fly deploy
fly status
fly logs
```

In your generated `fly.toml`, make sure the HTTP service points at port 3000
and that `force_https = true` is set under `[http_service]`. Add a persistent
volume mount, use one active instance for the personal token store, and confirm
the proxy sanitizes forwarded headers before enabling `MCP_TRUST_PROXY=1`.
The commands above are a deployment outline, not the initial OAuth bootstrap.

### Railway

[Railway](https://railway.app) auto-detects the Dockerfile.

1. Create a new project from this GitHub repo (or `railway up` from a clone).
2. In **Variables**, add `MCP_AUTH_TOKEN`, `WHOOP_CLIENT_ID` and
  `WHOOP_CLIENT_SECRET`. Set the service target port to `MCP_PORT` (default 3000).
3. Under **Settings → Networking**, generate a public domain. Railway
   terminates TLS for you.
4. Mount persistent storage at `/home/node/.whoop-mcp`, with private permissions
  and UID 1000 ownership, and securely provision the initial tokens.
5. Deploy a single instance. Health check path: `/health`. Enable trusted proxy
  mode only after verifying forwarded-header handling; check current hosting costs.

### Other platforms

Use a platform that supports a long-running Node process, Streamable HTTP,
persistent private token storage and controlled TLS/proxy forwarding. Ephemeral
filesystems, scale-to-zero restarts and multiple replicas need additional operational
planning. Never expose an unauthenticated token-bootstrap or health-data endpoint.

### Connecting from claude.ai (OAuth 2.1 connector)

Local Desktop/CLI setup uses stdio. HTTP clients supporting static bearer tokens
can authenticate directly with `MCP_AUTH_TOKEN`; remote OAuth clients use the
separate OAuth 2.1 connector with PKCE. This authorizes access to your MCP host,
not to WHOOP, and does not replace the initial WHOOP browser grant. Enable it
with the following settings alongside the required HTTP configuration:

```bash
fly secrets set \
  MCP_CONNECTOR_PASSWORD="$(openssl rand -base64 24)" \
  PUBLIC_URL="https://whoop-mcp-<your-suffix>.fly.dev" \
  ALLOWED_REDIRECT_URIS="https://claude.ai/api/mcp/auth_callback"
```

- `MCP_CONNECTOR_PASSWORD` (≥12 chars) — the human-facing password you'll type
  into the claude.ai connector dialog. Treat it like any other shared secret.
- `PUBLIC_URL` — the public `https://` origin claude.ai will reach. Used as
  the OAuth issuer (e.g. `https://example.com` → metadata at
  `/.well-known/oauth-authorization-server`).
- `ALLOWED_REDIRECT_URIS` — comma-separated **exact-match** allowlist. For
  claude.ai the value is `https://claude.ai/api/mcp/auth_callback`.
- Optional: `MCP_JWT_SECRET` overrides the JWT signing key (defaults to an
  HKDF derivation from `MCP_AUTH_TOKEN`); `MCP_OAUTH_CLIENT_ID` overrides the
  advertised client id (default `whoop-mcp-connector`).

In a supported claude.ai account, open Settings → Connectors → Add custom
connector, point it at `PUBLIC_URL/mcp`, and enter `MCP_CONNECTOR_PASSWORD` on
your host's authorization page. Confirm the exact callback URL required by your
client; features and account availability can change. These settings do not make
this a multi-user WHOOP service.
