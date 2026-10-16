import { describe, it, expect, vi } from "vitest";
import { createSupabaseRest, SupabaseError } from "../../src/storage/supabase-rest.js";

function mockFetch(response: Response): ReturnType<typeof vi.fn> {
  return vi.fn(async () => response);
}

function lastCall(fetchMock: ReturnType<typeof vi.fn>): { url: URL; init: RequestInit } {
  const call = fetchMock.mock.calls.at(-1) as [URL, RequestInit];
  return { url: call[0], init: call[1] };
}

describe("createSupabaseRest", () => {
  it("sends GET with filters and select=* to the REST endpoint", async () => {
    const fetchMock = mockFetch(new Response(JSON.stringify([{ id: 1 }]), { status: 200 }));
    const db = createSupabaseRest({
      url: "https://proj.supabase.co/",
      serviceKey: "sb_secret_abc",
      fetch: fetchMock as unknown as typeof fetch,
    });

    const rows = await db.select<{ id: number }>("whoop_tokens", { account_id: "eq.default" });

    expect(rows).toEqual([{ id: 1 }]);
    const { url, init } = lastCall(fetchMock);
    expect(url.origin + url.pathname).toBe("https://proj.supabase.co/rest/v1/whoop_tokens");
    expect(url.searchParams.get("select")).toBe("*");
    expect(url.searchParams.get("account_id")).toBe("eq.default");
    expect(init.method).toBe("GET");
  });

  it("sends new sb_secret keys only as apikey", async () => {
    const fetchMock = mockFetch(new Response("[]", { status: 200 }));
    const db = createSupabaseRest({
      url: "https://proj.supabase.co",
      serviceKey: "sb_secret_abc",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await db.select("t", {});
    const headers = lastCall(fetchMock).init.headers as Record<string, string>;
    expect(headers.apikey).toBe("sb_secret_abc");
    expect(headers.Authorization).toBeUndefined();
  });

  it("sends legacy JWT service keys as apikey and bearer", async () => {
    const fetchMock = mockFetch(new Response("[]", { status: 200 }));
    const db = createSupabaseRest({
      url: "https://proj.supabase.co",
      serviceKey: "eyJhbGciOi.jwt",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await db.select("t", {});
    const headers = lastCall(fetchMock).init.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer eyJhbGciOi.jwt");
  });

  it("maps onConflict to PostgREST resolution preferences", async () => {
    const fetchMock = vi.fn(async () => new Response("[]", { status: 201 }));
    const db = createSupabaseRest({
      url: "https://proj.supabase.co",
      serviceKey: "k",
      fetch: fetchMock as unknown as typeof fetch,
    });

    await db.insert("t", { a: 1 }, { onConflict: "merge" });
    let headers = lastCall(fetchMock).init.headers as Record<string, string>;
    expect(headers.Prefer).toBe("return=representation,resolution=merge-duplicates");
    expect(lastCall(fetchMock).init.body).toBe('{"a":1}');

    await db.insert("t", { a: 1 }, { onConflict: "ignore" });
    headers = lastCall(fetchMock).init.headers as Record<string, string>;
    expect(headers.Prefer).toBe("return=representation,resolution=ignore-duplicates");
  });

  it("uses PATCH and DELETE for update and remove", async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 204 }));
    const db = createSupabaseRest({
      url: "https://proj.supabase.co",
      serviceKey: "k",
      fetch: fetchMock as unknown as typeof fetch,
    });

    expect(await db.update("t", { id: "eq.1" }, { a: 2 })).toEqual([]);
    expect(lastCall(fetchMock).init.method).toBe("PATCH");
    expect(await db.remove("t", { id: "eq.1" })).toEqual([]);
    expect(lastCall(fetchMock).init.method).toBe("DELETE");
    expect(lastCall(fetchMock).url.searchParams.get("id")).toBe("eq.1");
  });

  it("throws SupabaseError with status on non-2xx", async () => {
    const fetchMock = mockFetch(
      new Response('{"message":"relation does not exist"}', { status: 404 })
    );
    const db = createSupabaseRest({
      url: "https://proj.supabase.co",
      serviceKey: "k",
      fetch: fetchMock as unknown as typeof fetch,
    });
    const error = await db.select("missing", {}).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SupabaseError);
    expect((error as SupabaseError).statusCode).toBe(404);
    expect((error as SupabaseError).message).toContain("relation does not exist");
  });

  it("throws SupabaseError on network failure", async () => {
    const fetchMock = vi.fn(async () => {
      throw new TypeError("fetch failed");
    });
    const db = createSupabaseRest({
      url: "https://proj.supabase.co",
      serviceKey: "k",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await expect(db.select("t", {})).rejects.toThrow("Unable to reach Supabase.");
  });
});
