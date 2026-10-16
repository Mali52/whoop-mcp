/**
 * WHOOP access-token provider backed by the Supabase token repository.
 *
 * WHOOP rotates refresh tokens, so two serverless instances refreshing with
 * the same refresh token would invalidate each other. Refreshes are therefore
 * single-flight across instances: one instance takes a short lease in the
 * database, the others wait for the new token version to appear.
 */

import {
  refreshAccessToken,
  toOAuthTokens,
  type OAuthConfig,
  type TokenResponse,
} from "../auth/oauth.js";
import { isTokenExpired } from "../auth/token-store.js";
import { WhoopNetworkError, WhoopNotConnectedError } from "../api/client.js";
import type { StoredWhoopTokens, WhoopTokenRepository } from "../storage/supabase-stores.js";

/** How long a refresh lease is held before other instances may take over. */
export const REFRESH_LEASE_MS = 20_000;

export interface WhoopSessionOptions {
  repository: WhoopTokenRepository;
  oauthConfig: OAuthConfig;
  /** Absolute URL of the browser page that (re)connects WHOOP. */
  connectUrl: string;
  /** Poll interval while another instance refreshes (default 400ms). */
  pollIntervalMs?: number;
  /** Max time to wait for another instance's refresh (default 10s). */
  maxWaitMs?: number;
}

export interface WhoopSession {
  /** Current access token, refreshing first if it is expired. */
  getAccessToken(): Promise<string>;
  /** Force a refresh (used after a WHOOP 401). Returns the new access token. */
  refresh(): Promise<string>;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function createWhoopSession(options: WhoopSessionOptions): WhoopSession {
  const { repository, oauthConfig, connectUrl } = options;
  const pollIntervalMs = options.pollIntervalMs ?? 400;
  const maxWaitMs = options.maxWaitMs ?? 10_000;

  /** The record whose access token this instance last handed out. */
  let lastSeen: StoredWhoopTokens | null = null;

  async function loadOrThrow(): Promise<StoredWhoopTokens> {
    const stored = await repository.load();
    if (!stored) throw new WhoopNotConnectedError(connectUrl);
    return stored;
  }

  async function refreshFrom(seen: StoredWhoopTokens): Promise<string> {
    if (await repository.tryLock(REFRESH_LEASE_MS)) {
      try {
        // Another instance may have refreshed between our read and the lock.
        const latest = await loadOrThrow();
        if (latest.version !== seen.version && !isTokenExpired(latest.tokens)) {
          await repository.unlock();
          lastSeen = latest;
          return latest.tokens.access_token;
        }

        let refreshed: TokenResponse;
        try {
          refreshed = await refreshAccessToken(latest.tokens.refresh_token, oauthConfig);
        } catch (error) {
          if (error instanceof WhoopNetworkError) throw error;
          throw new WhoopNotConnectedError(
            connectUrl,
            "WHOOP authorization expired or was revoked."
          );
        }
        const next = toOAuthTokens(refreshed, latest.tokens.refresh_token);
        await repository.commitRefresh(next);
        lastSeen = null;
        return next.access_token;
      } catch (error) {
        await repository.unlock().catch(() => undefined);
        throw error;
      }
    }

    // Someone else holds the lease — wait for their new token version.
    const deadline = Date.now() + maxWaitMs;
    while (Date.now() < deadline) {
      await delay(pollIntervalMs);
      const latest = await loadOrThrow();
      if (latest.version !== seen.version) {
        lastSeen = latest;
        return latest.tokens.access_token;
      }
    }
    throw new Error("Timed out waiting for a concurrent WHOOP token refresh. Retry the request.");
  }

  return {
    async getAccessToken(): Promise<string> {
      const stored = await loadOrThrow();
      if (isTokenExpired(stored.tokens)) return refreshFrom(stored);
      lastSeen = stored;
      return stored.tokens.access_token;
    },

    async refresh(): Promise<string> {
      return refreshFrom(lastSeen ?? (await loadOrThrow()));
    },
  };
}
