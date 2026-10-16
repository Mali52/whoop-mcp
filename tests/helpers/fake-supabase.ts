/**
 * In-memory stand-in for the PostgREST client. Interprets the small filter
 * subset the stores use: eq., is.null, gt., lt. and or=(…) of those.
 */

import type { Filters, InsertOptions, SupabaseRest } from "../../src/storage/supabase-rest.js";

type Row = Record<string, unknown>;

const PRIMARY_KEYS: Record<string, string> = {
  whoop_tokens: "account_id",
  oauth_auth_codes: "code_hash",
  oauth_used_jtis: "jti",
  whoop_oauth_states: "state_hash",
  auth_failures: "id",
};

function compare(a: unknown, b: string): number {
  if (typeof a === "number") return a - Number(b);
  const ta = Date.parse(String(a));
  const tb = Date.parse(b);
  if (!Number.isNaN(ta) && !Number.isNaN(tb)) return ta - tb;
  return String(a).localeCompare(b);
}

function matchesCondition(row: Row, column: string, expression: string): boolean {
  const value = row[column];
  if (expression === "is.null") return value === null || value === undefined;
  const [op, ...rest] = expression.split(".");
  const operand = rest.join(".").replace(/^"|"$/g, "");
  if (op === "eq") return String(value) === operand;
  if (value === null || value === undefined) return false;
  if (op === "gt") return compare(value, operand) > 0;
  if (op === "lt") return compare(value, operand) < 0;
  throw new Error(`fake-supabase: unsupported operator ${expression}`);
}

function matches(row: Row, filters: Filters): boolean {
  return Object.entries(filters).every(([column, expression]) => {
    if (column === "select" || column === "limit") return true;
    if (column === "or") {
      const inner = expression.replace(/^\(|\)$/g, "").split(",");
      return inner.some((clause) => {
        const dot = clause.indexOf(".");
        return matchesCondition(row, clause.slice(0, dot), clause.slice(dot + 1));
      });
    }
    return matchesCondition(row, column, expression);
  });
}

export interface FakeSupabase extends SupabaseRest {
  tables: Map<string, Row[]>;
  rows(table: string): Row[];
}

export function createFakeSupabase(): FakeSupabase {
  const tables = new Map<string, Row[]>();
  let nextId = 0;
  const rows = (table: string): Row[] => {
    let list = tables.get(table);
    if (!list) {
      list = [];
      tables.set(table, list);
    }
    return list;
  };
  const clone = <T>(value: unknown): T => structuredClone(value) as T;

  return {
    tables,
    rows,
    async select<T>(table: string, filters: Filters): Promise<T[]> {
      const hit = rows(table).filter((r) => matches(r, filters));
      return clone<T[]>(filters.limit ? hit.slice(0, Number(filters.limit)) : hit);
    },
    async insert<T>(table: string, row: Row, options?: InsertOptions): Promise<T[]> {
      const list = rows(table);
      const pk = PRIMARY_KEYS[table] ?? "id";
      if (pk === "id" && row.id === undefined) row = { ...row, id: ++nextId };
      const existing = list.find((r) => r[pk] === row[pk]);
      if (existing) {
        if (options?.onConflict === "ignore") return [];
        if (options?.onConflict === "merge") {
          Object.assign(existing, row);
          return clone<T[]>([existing]);
        }
        throw new Error(`fake-supabase: duplicate key ${String(row[pk])}`);
      }
      list.push({ ...row });
      return clone<T[]>([row]);
    },
    async update<T>(table: string, filters: Filters, patch: Row): Promise<T[]> {
      const hit = rows(table).filter((r) => matches(r, filters));
      for (const r of hit) Object.assign(r, patch);
      return clone<T[]>(hit);
    },
    async remove<T>(table: string, filters: Filters): Promise<T[]> {
      const list = rows(table);
      const hit = list.filter((r) => matches(r, filters));
      tables.set(
        table,
        list.filter((r) => !hit.includes(r))
      );
      return clone<T[]>(hit);
    },
  };
}
