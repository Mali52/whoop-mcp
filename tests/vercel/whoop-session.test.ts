import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createWhoopSession, type WhoopSession } from "../../src/vercel/whoop-session.js";
import { createSupabaseTokenRepository } from "../../src/storage/supabase-stores.js";
import { deriveEncryptionKey } from "../../src/storage/token-crypto.js";
import { WhoopNetworkError, WhoopNotConnectedError } from "../../src/api/client.js";
import type { WhoopTokenRepository } from "../../src/storage/supabase-stores.js";
import { createFakeSupabase } from "../helpers/fake-supabase.js";

const CONNECT_URL = "https://whoop.example.com/whoop/connect";
const OAUTH = { clientId: "id", clientSecret: "secret" };

function tokenResponse(n: number): Response {
  return new Response(
    JSON.stringify({
      access_token: `access-${n}`,
      refresh_token: `refresh-${n}`,
      expires_in: 3600,
      token_type: "Bearer",
      scope: "offline",
    }),
    { status: 200 }
  );
}

let repo: WhoopTokenRepository;
let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(async () => {
  repo = createSupabaseTokenRepository(createFakeSupabase(), await deriveEncryptionKey("k"));
  fetchMock = vi.fn(async () => tokenResponse(2));
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function session(overrides: Partial<Parameters<typeof createWhoopSession>[0]> = {}): WhoopSession {
  return createWhoopSession({
    repository: repo,
    oauthConfig: OAUTH,
    connectUrl: CONNECT_URL,
    pollIntervalMs: 5,
    maxWaitMs: 200,
    ...overrides,
  });
}

describe("createWhoopSession", () => {
  it("throws WhoopNotConnectedError with the connect URL when no tokens exist", async () => {
    const error = await session()
      .getAccessToken()
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(WhoopNotConnectedError);
    expect((error as Error).message).toContain(CONNECT_URL);
  });

  it("returns a valid stored token without refreshing", async () => {
    await repo.save({
      access_token: "access-1",
      refresh_token: "refresh-1",
      expires_at: Date.now() + 3_600_000,
      token_type: "Bearer",
    });
    expect(await session().getAccessToken()).toBe("access-1");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refreshes expired tokens and persists the rotated refresh token", async () => {
    await repo.save({
      access_token: "access-1",
      refresh_token: "refresh-1",
      expires_at: Date.now() - 1000,
      token_type: "Bearer",
    });

    expect(await session().getAccessToken()).toBe("access-2");
    const body = String((fetchMock.mock.calls[0] as [string, RequestInit])[1].body);
    expect(body).toContain("refresh_token=refresh-1");
    expect((await repo.load())?.tokens.refresh_token).toBe("refresh-2");
    // lease released
    expect(await repo.tryLock(1000)).toBe(true);
  });

  it("forces a refresh after a 401 even if the token looks valid", async () => {
    await repo.save({
      access_token: "access-1",
      refresh_token: "refresh-1",
      expires_at: Date.now() + 3_600_000,
      token_type: "Bearer",
    });
    const s = session();
    await s.getAccessToken();
    expect(await s.refresh()).toBe("access-2");
  });

  it("only one of two concurrent sessions calls WHOOP; the other reuses the result", async () => {
    await repo.save({
      access_token: "access-1",
      refresh_token: "refresh-1",
      expires_at: Date.now() - 1000,
      token_type: "Bearer",
    });
    let release: () => void = () => undefined;
    fetchMock.mockImplementationOnce(
      () =>
        new Promise<Response>((resolve) => {
          release = () => resolve(tokenResponse(2));
        })
    );

    const first = session().getAccessToken();
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const second = session().getAccessToken();
    release();

    expect(await first).toBe("access-2");
    expect(await second).toBe("access-2");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("times out when another instance holds the lease and never finishes", async () => {
    await repo.save({
      access_token: "access-1",
      refresh_token: "refresh-1",
      expires_at: Date.now() - 1000,
      token_type: "Bearer",
    });
    await repo.tryLock(60_000);
    await expect(session({ maxWaitMs: 30 }).getAccessToken()).rejects.toThrow("Timed out waiting");
  });

  it("asks the user to reconnect when WHOOP rejects the refresh token", async () => {
    await repo.save({
      access_token: "access-1",
      refresh_token: "revoked",
      expires_at: Date.now() - 1000,
      token_type: "Bearer",
    });
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ error_description: "invalid_grant" }), { status: 400 })
    );
    const error = await session()
      .getAccessToken()
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(WhoopNotConnectedError);
    expect((error as Error).message).toContain("expired or was revoked");
    expect(await repo.tryLock(1000)).toBe(true);
  });

  it("propagates network errors without asking to reconnect", async () => {
    await repo.save({
      access_token: "access-1",
      refresh_token: "refresh-1",
      expires_at: Date.now() - 1000,
      token_type: "Bearer",
    });
    fetchMock.mockRejectedValueOnce(new TypeError("fetch failed"));
    await expect(session().getAccessToken()).rejects.toBeInstanceOf(WhoopNetworkError);
  });
});
