-- WHOOP MCP — security hardening.

-- Failed password attempts on /authorize and /whoop/connect, counted across
-- all serverless instances for a global brute-force lock.
create table if not exists public.auth_failures (
  id      bigint generated always as identity primary key,
  at      timestamptz not null default now(),
  source  text        not null,
  ip      text        not null
);
create index if not exists auth_failures_at_idx on public.auth_failures (at);

alter table public.auth_failures enable row level security;
revoke all on public.auth_failures from anon, authenticated;

-- The trigger function is never meant to be called through the API.
revoke execute on function public.whoop_tokens_touch_updated_at() from public, anon, authenticated;

-- This project only serves the MCP server: future tables and functions must
-- not be exposed to the anon/authenticated roles by default.
alter default privileges for role postgres in schema public
  revoke all on tables from anon, authenticated;
alter default privileges for role postgres in schema public
  revoke all on sequences from anon, authenticated;
alter default privileges for role postgres in schema public
  revoke execute on functions from anon, authenticated, public;
