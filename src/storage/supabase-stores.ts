/**
 * Supabase-backed state for the serverless (Vercel) deployment.
 *
 * Serverless instances share no memory, so everything the long-running
 * server keeps in-process or on disk lives in Postgres instead:
 *   - whoop_tokens         WHOOP OAuth tokens (encrypted at rest)
 *   - oauth_auth_codes     connector authorization codes (hashed, one-time)
 *   - oauth_used_jtis      consumed connector refresh-token jtis
 *   - whoop_oauth_states   pending WHOOP connect flows (state + PKCE verifier)
 *
 * Schema: supabase/migrations/*_whoop_mcp_init.sql
 */

import { createHash } from "node:crypto";
import type { OAuthTokens } from "../auth/token-store.js";
import type {
  AuthCodeInput,
  AuthCodeRecord,
  AuthCodeRepository,
  UsedJtiRepository,
} from "../transport/oauth-helpers.js";
import { AUTH_CODE_TTL_MS } from "../transport/oauth-helpers.js";
import type { SupabaseRest } from "./supabase-rest.js";
import { decryptString, encryptString } from "./token-crypto.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const TABLE_WHOOP_TOKENS = "whoop_tokens";
export const TABLE_AUTH_CODES = "oauth_auth_codes";
export const TABLE_USED_JTIS = "oauth_used_jtis";
export const TABLE_WHOOP_STATES = "whoop_oauth_states";

/** Single-user deployment: one WHOOP account per server. */
export const DEFAULT_ACCOUNT_ID = "default";

/** Pending WHOOP connect flows expire after 10 minutes. */
export const WHOOP_STATE_TTL_MS = 10 * 60_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Codes and states are stored hashed — a DB read never yields a usable value. */
export function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

// ---------------------------------------------------------------------------
// WHOOP tokens
// ---------------------------------------------------------------------------

interface WhoopTokenRow {
  account_id: string;
  access_token: string;
  refresh_token: string;
  expires_at: number;
  token_type: string;
  version: number;
  refresh_lock_until: string | null;
}

export interface StoredWhoopTokens {
  tokens: OAuthTokens;
  /** Changes on every write — used to detect refreshes by other instances. */
  version: number;
}

export interface WhoopTokenRepository {
  load(): Promise<StoredWhoopTokens | null>;
  /** Insert or overwrite tokens (initial connect). Clears any refresh lock. */
  save(tokens: OAuthTokens): Promise<void>;
  /** Try to take the refresh lease. Returns false if another instance holds it. */
  tryLock(leaseMs: number): Promise<boolean>;
  /** Store refreshed tokens and release the lease. */
  commitRefresh(tokens: OAuthTokens): Promise<void>;
  /** Release the lease without changing tokens. */
  unlock(): Promise<void>;
  /** Remove stored tokens (disconnect). */
  remove(): Promise<void>;
}

export function createSupabaseTokenRepository(
  db: SupabaseRest,
  encryptionKey: Buffer,
  accountId: string = DEFAULT_ACCOUNT_ID
): WhoopTokenRepository {
  const byAccount = { account_id: `eq.${accountId}` };

  function toRow(tokens: OAuthTokens): Record<string, unknown> {
    return {
      account_id: accountId,
      access_token: encryptString(tokens.access_token, encryptionKey),
      refresh_token: encryptString(tokens.refresh_token, encryptionKey),
      expires_at: tokens.expires_at,
      token_type: tokens.token_type,
      version: Date.now(),
      refresh_lock_until: null,
    };
  }

  return {
    async load(): Promise<StoredWhoopTokens | null> {
      const [row] = await db.select<WhoopTokenRow>(TABLE_WHOOP_TOKENS, byAccount);
      if (!row) return null;
      let accessToken: string;
      let refreshToken: string;
      try {
        accessToken = decryptString(row.access_token, encryptionKey);
        refreshToken = decryptString(row.refresh_token, encryptionKey);
      } catch {
        // Encryption secret changed (or row tampered) — the tokens are
        // unusable, so treat the account as disconnected and force a reconnect.
        console.error("Stored WHOOP tokens could not be decrypted; reconnect WHOOP.");
        return null;
      }
      return {
        tokens: {
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_at: Number(row.expires_at),
          token_type: row.token_type,
        },
        version: Number(row.version),
      };
    },

    async save(tokens: OAuthTokens): Promise<void> {
      await db.insert(TABLE_WHOOP_TOKENS, toRow(tokens), { onConflict: "merge" });
    },

    async tryLock(leaseMs: number): Promise<boolean> {
      const now = Date.now();
      const rows = await db.update<WhoopTokenRow>(
        TABLE_WHOOP_TOKENS,
        {
          ...byAccount,
          or: `(refresh_lock_until.is.null,refresh_lock_until.lt."${iso(now)}")`,
        },
        { refresh_lock_until: iso(now + leaseMs) }
      );
      return rows.length > 0;
    },

    async commitRefresh(tokens: OAuthTokens): Promise<void> {
      await db.update(TABLE_WHOOP_TOKENS, byAccount, toRow(tokens));
    },

    async unlock(): Promise<void> {
      await db.update(TABLE_WHOOP_TOKENS, byAccount, { refresh_lock_until: null });
    },

    async remove(): Promise<void> {
      await db.remove(TABLE_WHOOP_TOKENS, byAccount);
    },
  };
}

// ---------------------------------------------------------------------------
// Connector authorization codes
// ---------------------------------------------------------------------------

interface AuthCodeRow {
  code_hash: string;
  payload: AuthCodeInput;
  expires_at: string;
  consumed_at: string | null;
}

function toAuthCodeRecord(row: AuthCodeRow): AuthCodeRecord {
  return {
    ...row.payload,
    expiresAt: Date.parse(row.expires_at),
    consumed: row.consumed_at !== null,
  };
}

export function createSupabaseAuthCodeStore(
  db: SupabaseRest,
  options: { ttlMs?: number } = {}
): AuthCodeRepository {
  const ttlMs = options.ttlMs ?? AUTH_CODE_TTL_MS;

  function liveFilter(code: string): Record<string, string> {
    return {
      code_hash: `eq.${sha256Hex(code)}`,
      consumed_at: "is.null",
      expires_at: `gt.${iso(Date.now())}`,
    };
  }

  return {
    async store(code: string, input: AuthCodeInput): Promise<void> {
      const now = Date.now();
      // Opportunistic cleanup keeps the table tiny without a cron job.
      await db.remove(TABLE_AUTH_CODES, { expires_at: `lt.${iso(now - ttlMs)}` });
      await db.insert(TABLE_AUTH_CODES, {
        code_hash: sha256Hex(code),
        payload: input,
        expires_at: iso(now + ttlMs),
        consumed_at: null,
      });
    },

    async peek(code: string): Promise<AuthCodeRecord | null> {
      const [row] = await db.select<AuthCodeRow>(TABLE_AUTH_CODES, liveFilter(code));
      return row ? toAuthCodeRecord(row) : null;
    },

    async consume(code: string): Promise<AuthCodeRecord | null> {
      // Conditional UPDATE is atomic: only one concurrent caller gets the row.
      const [row] = await db.update<AuthCodeRow>(TABLE_AUTH_CODES, liveFilter(code), {
        consumed_at: iso(Date.now()),
      });
      return row ? toAuthCodeRecord(row) : null;
    },
  };
}

// ---------------------------------------------------------------------------
// Consumed refresh-token jtis
// ---------------------------------------------------------------------------

export function createSupabaseUsedJtiStore(db: SupabaseRest): UsedJtiRepository {
  return {
    async markUsed(jti: string, expiresAtSeconds: number): Promise<boolean> {
      await db.remove(TABLE_USED_JTIS, { expires_at: `lt.${iso(Date.now())}` });
      const inserted = await db.insert(
        TABLE_USED_JTIS,
        { jti, expires_at: iso(expiresAtSeconds * 1000) },
        { onConflict: "ignore" }
      );
      return inserted.length > 0;
    },
  };
}

// ---------------------------------------------------------------------------
// Pending WHOOP connect flows
// ---------------------------------------------------------------------------

interface WhoopStateRow {
  state_hash: string;
  code_verifier: string;
  expires_at: string;
}

export interface WhoopStateStore {
  create(state: string, codeVerifier: string): Promise<void>;
  /** One-time lookup: returns the PKCE verifier and deletes the state. */
  consume(state: string): Promise<string | null>;
}

export function createSupabaseWhoopStateStore(
  db: SupabaseRest,
  options: { ttlMs?: number } = {}
): WhoopStateStore {
  const ttlMs = options.ttlMs ?? WHOOP_STATE_TTL_MS;

  return {
    async create(state: string, codeVerifier: string): Promise<void> {
      const now = Date.now();
      await db.remove(TABLE_WHOOP_STATES, { expires_at: `lt.${iso(now)}` });
      await db.insert(TABLE_WHOOP_STATES, {
        state_hash: sha256Hex(state),
        code_verifier: codeVerifier,
        expires_at: iso(now + ttlMs),
      });
    },

    async consume(state: string): Promise<string | null> {
      const [row] = await db.remove<WhoopStateRow>(TABLE_WHOOP_STATES, {
        state_hash: `eq.${sha256Hex(state)}`,
        expires_at: `gt.${iso(Date.now())}`,
      });
      return row?.code_verifier ?? null;
    },
  };
}
