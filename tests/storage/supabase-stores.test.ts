import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import {
  createSupabaseAuthCodeStore,
  createSupabaseTokenRepository,
  createSupabaseUsedJtiStore,
  createSupabaseWhoopStateStore,
  sha256Hex,
} from "../../src/storage/supabase-stores.js";
import { deriveEncryptionKey } from "../../src/storage/token-crypto.js";
import type { OAuthTokens } from "../../src/auth/token-store.js";
import { createFakeSupabase, type FakeSupabase } from "../helpers/fake-supabase.js";

const TOKENS: OAuthTokens = {
  access_token: "access-1",
  refresh_token: "refresh-1",
  expires_at: 1_900_000_000_000,
  token_type: "Bearer",
};

const CODE_INPUT = {
  clientId: "client",
  codeChallenge: "challenge",
  codeChallengeMethod: "S256" as const,
  redirectUri: "https://claude.ai/api/mcp/auth_callback",
  state: "st",
  scopes: ["mcp"],
};

let db: FakeSupabase;
let key: Buffer;

beforeEach(async () => {
  db = createFakeSupabase();
  key = await deriveEncryptionKey("test-secret");
});

afterEach(() => {
  vi.useRealTimers();
});

describe("SupabaseTokenRepository", () => {
  it("returns null when nothing is stored", async () => {
    const repo = createSupabaseTokenRepository(db, key);
    expect(await repo.load()).toBeNull();
  });

  it("encrypts tokens at rest and decrypts on load", async () => {
    const repo = createSupabaseTokenRepository(db, key);
    await repo.save(TOKENS);

    const [row] = db.rows("whoop_tokens");
    expect(row?.access_token).not.toBe("access-1");
    expect(row?.refresh_token).not.toBe("refresh-1");

    const loaded = await repo.load();
    expect(loaded?.tokens).toEqual(TOKENS);
  });

  it("returns null when tokens were encrypted with another key", async () => {
    await createSupabaseTokenRepository(db, key).save(TOKENS);
    const otherKey = await deriveEncryptionKey("rotated");
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    expect(await createSupabaseTokenRepository(db, otherKey).load()).toBeNull();
    spy.mockRestore();
  });

  it("overwrites on save (reconnect)", async () => {
    const repo = createSupabaseTokenRepository(db, key);
    await repo.save(TOKENS);
    await repo.save({ ...TOKENS, access_token: "access-2" });
    expect(db.rows("whoop_tokens")).toHaveLength(1);
    expect((await repo.load())?.tokens.access_token).toBe("access-2");
  });

  it("grants the refresh lease to only one caller until it expires", async () => {
    vi.useFakeTimers({ now: 1_000_000 });
    const repo = createSupabaseTokenRepository(db, key);
    await repo.save(TOKENS);

    expect(await repo.tryLock(20_000)).toBe(true);
    expect(await repo.tryLock(20_000)).toBe(false);

    vi.setSystemTime(1_000_000 + 21_000);
    expect(await repo.tryLock(20_000)).toBe(true);
  });

  it("commitRefresh stores new tokens, bumps version and releases the lease", async () => {
    vi.useFakeTimers({ now: 1_000_000 });
    const repo = createSupabaseTokenRepository(db, key);
    await repo.save(TOKENS);
    const before = await repo.load();
    await repo.tryLock(20_000);

    vi.setSystemTime(1_000_500);
    await repo.commitRefresh({ ...TOKENS, access_token: "access-2" });

    const after = await repo.load();
    expect(after?.tokens.access_token).toBe("access-2");
    expect(after?.version).not.toBe(before?.version);
    expect(await repo.tryLock(20_000)).toBe(true);
  });

  it("unlock releases the lease without touching tokens", async () => {
    const repo = createSupabaseTokenRepository(db, key);
    await repo.save(TOKENS);
    await repo.tryLock(20_000);
    await repo.unlock();
    expect(await repo.tryLock(20_000)).toBe(true);
    expect((await repo.load())?.tokens).toEqual(TOKENS);
  });

  it("remove deletes the account", async () => {
    const repo = createSupabaseTokenRepository(db, key);
    await repo.save(TOKENS);
    await repo.remove();
    expect(await repo.load()).toBeNull();
  });
});

describe("SupabaseAuthCodeStore", () => {
  it("stores codes hashed and peeks without consuming", async () => {
    const store = createSupabaseAuthCodeStore(db);
    await store.store("code-1", CODE_INPUT);

    const [row] = db.rows("oauth_auth_codes");
    expect(row?.code_hash).toBe(sha256Hex("code-1"));
    expect(JSON.stringify(row)).not.toContain("code-1");

    expect((await store.peek("code-1"))?.codeChallenge).toBe("challenge");
    expect((await store.peek("code-1"))?.consumed).toBe(false);
  });

  it("consumes a code exactly once", async () => {
    const store = createSupabaseAuthCodeStore(db);
    await store.store("code-1", CODE_INPUT);

    const first = await store.consume("code-1");
    expect(first?.clientId).toBe("client");
    expect(first?.consumed).toBe(true);
    expect(await store.consume("code-1")).toBeNull();
    expect(await store.peek("code-1")).toBeNull();
  });

  it("rejects expired codes", async () => {
    vi.useFakeTimers({ now: 1_000_000 });
    const store = createSupabaseAuthCodeStore(db, { ttlMs: 1000 });
    await store.store("code-1", CODE_INPUT);
    vi.setSystemTime(1_002_000);
    expect(await store.peek("code-1")).toBeNull();
    expect(await store.consume("code-1")).toBeNull();
  });

  it("cleans up long-expired codes on store", async () => {
    vi.useFakeTimers({ now: 1_000_000 });
    const store = createSupabaseAuthCodeStore(db, { ttlMs: 1000 });
    await store.store("old", CODE_INPUT);
    vi.setSystemTime(1_010_000);
    await store.store("new", CODE_INPUT);
    expect(db.rows("oauth_auth_codes")).toHaveLength(1);
  });

  it("returns null for unknown codes", async () => {
    const store = createSupabaseAuthCodeStore(db);
    expect(await store.peek("nope")).toBeNull();
    expect(await store.consume("nope")).toBeNull();
  });
});

describe("SupabaseUsedJtiStore", () => {
  it("returns true on first use and false on replay", async () => {
    const store = createSupabaseUsedJtiStore(db);
    const exp = Math.floor(Date.now() / 1000) + 3600;
    expect(await store.markUsed("jti-1", exp)).toBe(true);
    expect(await store.markUsed("jti-1", exp)).toBe(false);
    expect(await store.markUsed("jti-2", exp)).toBe(true);
  });

  it("purges expired jtis", async () => {
    vi.useFakeTimers({ now: 1_000_000 });
    const store = createSupabaseUsedJtiStore(db);
    await store.markUsed("old", 1_000_000 / 1000 + 1);
    vi.setSystemTime(1_005_000);
    await store.markUsed("new", 1_005_000 / 1000 + 100);
    expect(db.rows("oauth_used_jtis").map((r) => r.jti)).toEqual(["new"]);
  });
});

describe("SupabaseWhoopStateStore", () => {
  it("returns the verifier once and deletes the state", async () => {
    const store = createSupabaseWhoopStateStore(db);
    await store.create("state-1", "verifier-1");
    expect(db.rows("whoop_oauth_states")[0]?.state_hash).toBe(sha256Hex("state-1"));
    expect(await store.consume("state-1")).toBe("verifier-1");
    expect(await store.consume("state-1")).toBeNull();
  });

  it("rejects expired states", async () => {
    vi.useFakeTimers({ now: 1_000_000 });
    const store = createSupabaseWhoopStateStore(db, { ttlMs: 1000 });
    await store.create("state-1", "verifier-1");
    vi.setSystemTime(1_002_000);
    expect(await store.consume("state-1")).toBeNull();
  });
});
