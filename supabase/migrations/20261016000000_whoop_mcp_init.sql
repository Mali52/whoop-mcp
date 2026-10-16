-- WHOOP MCP — serverless state (Vercel deployment).
--
-- All tables are accessed exclusively by the server with the service-role
-- (secret) key. Row Level Security is enabled with NO policies, so the
-- anon/publishable key and authenticated users can never read them.

-- WHOOP OAuth tokens (AES-256-GCM encrypted by the server before insert).
create table if not exists public.whoop_tokens (
  account_id          text primary key default 'default',
  access_token        text        not null,
  refresh_token       text        not null,
  expires_at          bigint      not null,          -- epoch milliseconds
  token_type          text        not null default 'Bearer',
  version             bigint      not null default 0, -- bumps on every write
  refresh_lock_until  timestamptz,                    -- lease for single-flight refresh
  updated_at          timestamptz not null default now()
);

-- Connector (claude.ai) authorization codes — stored as SHA-256 hashes.
create table if not exists public.oauth_auth_codes (
  code_hash    text primary key,
  payload      jsonb       not null,
  expires_at   timestamptz not null,
  consumed_at  timestamptz
);
create index if not exists oauth_auth_codes_expires_at_idx on public.oauth_auth_codes (expires_at);

-- Consumed connector refresh-token jtis (replay detection).
create table if not exists public.oauth_used_jtis (
  jti         text primary key,
  expires_at  timestamptz not null
);
create index if not exists oauth_used_jtis_expires_at_idx on public.oauth_used_jtis (expires_at);

-- Pending WHOOP connect flows (OAuth state hash + PKCE verifier).
create table if not exists public.whoop_oauth_states (
  state_hash     text primary key,
  code_verifier  text        not null,
  expires_at     timestamptz not null
);

-- Keep updated_at current.
create or replace function public.whoop_tokens_touch_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists whoop_tokens_touch_updated_at on public.whoop_tokens;
create trigger whoop_tokens_touch_updated_at
  before update on public.whoop_tokens
  for each row execute function public.whoop_tokens_touch_updated_at();

-- Lock everything down: server-side service role only.
alter table public.whoop_tokens       enable row level security;
alter table public.oauth_auth_codes   enable row level security;
alter table public.oauth_used_jtis    enable row level security;
alter table public.whoop_oauth_states enable row level security;

revoke all on public.whoop_tokens, public.oauth_auth_codes, public.oauth_used_jtis, public.whoop_oauth_states
  from anon, authenticated;
