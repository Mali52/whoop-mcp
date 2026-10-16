/**
 * Minimal Supabase (PostgREST) client built on native `fetch`.
 *
 * Avoids pulling in `@supabase/supabase-js` — the serverless deployment only
 * needs a handful of table operations, all authenticated with the
 * service-role (secret) key. Never expose that key to browsers.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SupabaseRestOptions {
  /** Project URL, e.g. https://abcd.supabase.co */
  url: string;
  /** Service-role JWT or `sb_secret_...` key. Server-side only. */
  serviceKey: string;
  /** Injectable fetch (tests). Defaults to global fetch. */
  fetch?: typeof fetch;
}

/** PostgREST filter map: column → operator expression, e.g. `{ id: "eq.default" }` */
export type Filters = Record<string, string>;

export interface SupabaseRest {
  select<T>(table: string, filters: Filters): Promise<T[]>;
  insert<T>(table: string, row: Record<string, unknown>, options?: InsertOptions): Promise<T[]>;
  update<T>(table: string, filters: Filters, patch: Record<string, unknown>): Promise<T[]>;
  remove<T>(table: string, filters: Filters): Promise<T[]>;
}

export interface InsertOptions {
  /** `merge` upserts on the primary key; `ignore` skips rows that already exist. */
  onConflict?: "merge" | "ignore";
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** Thrown when Supabase is unreachable or returns a non-2xx response. */
export class SupabaseError extends Error {
  public override readonly name = "SupabaseError";

  constructor(
    message: string,
    public readonly statusCode?: number,
    options?: { cause?: unknown }
  ) {
    super(message, options);
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a PostgREST client for the given Supabase project.
 *
 * Every call returns the affected rows (`Prefer: return=representation`), so
 * conditional updates/deletes double as atomic compare-and-swap operations:
 * an empty array means no row matched.
 */
export function createSupabaseRest(options: SupabaseRestOptions): SupabaseRest {
  const baseUrl = `${options.url.replace(/\/+$/, "")}/rest/v1`;
  const doFetch = options.fetch ?? fetch;

  const headers: Record<string, string> = {
    apikey: options.serviceKey,
    "Content-Type": "application/json",
    Accept: "application/json",
  };
  // Legacy service_role keys are JWTs and go in Authorization too. New
  // `sb_secret_...` keys are not JWTs and must only be sent as `apikey`.
  if (options.serviceKey.startsWith("eyJ")) {
    headers.Authorization = `Bearer ${options.serviceKey}`;
  }

  async function request<T>(
    method: string,
    table: string,
    filters: Filters,
    body?: unknown,
    prefer: string[] = []
  ): Promise<T[]> {
    const url = new URL(`${baseUrl}/${encodeURIComponent(table)}`);
    for (const [column, expression] of Object.entries(filters)) {
      url.searchParams.set(column, expression);
    }

    let response: Response;
    try {
      response = await doFetch(url, {
        method,
        headers: { ...headers, Prefer: ["return=representation", ...prefer].join(",") },
        ...(body !== undefined && { body: JSON.stringify(body) }),
      });
    } catch (error) {
      throw new SupabaseError("Unable to reach Supabase.", undefined, { cause: error });
    }

    if (!response.ok) {
      const detail = await response.text().catch(() => "");
      throw new SupabaseError(
        `Supabase ${method} ${table} failed (${response.status})${detail ? `: ${detail.slice(0, 300)}` : ""}`,
        response.status
      );
    }

    const text = await response.text();
    if (!text) return [];
    return JSON.parse(text) as T[];
  }

  return {
    select: <T>(table: string, filters: Filters) => {
      return request<T>("GET", table, { select: "*", ...filters });
    },
    insert: <T>(table: string, row: Record<string, unknown>, insertOptions?: InsertOptions) => {
      const prefer: string[] = [];
      if (insertOptions?.onConflict === "merge") prefer.push("resolution=merge-duplicates");
      if (insertOptions?.onConflict === "ignore") prefer.push("resolution=ignore-duplicates");
      return request<T>("POST", table, {}, row, prefer);
    },
    update: <T>(table: string, filters: Filters, patch: Record<string, unknown>) => {
      return request<T>("PATCH", table, filters, patch);
    },
    remove: <T>(table: string, filters: Filters) => {
      return request<T>("DELETE", table, filters);
    },
  };
}
