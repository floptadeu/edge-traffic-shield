// Utilidades HTTP da API: JSON, erros e cursor de paginação.

import { base64urlDecode, base64urlEncode } from "../lib/crypto";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public details?: unknown,
  ) {
    super(message);
  }
}

export function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data, null, 2) + "\n", {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
  });
}

export async function readJson<T = Record<string, unknown>>(request: Request): Promise<T> {
  try {
    const v = (await request.json()) as T;
    if (typeof v !== "object" || v === null) throw new Error();
    return v;
  } catch {
    throw new ApiError(400, "corpo JSON inválido");
  }
}

// Cursor opaco: base64url(JSON). Keyset pagination, nunca OFFSET.
export function encodeCursor(obj: Record<string, string | number>): string {
  return base64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

export function decodeCursor<T extends Record<string, unknown>>(raw: string | null): T | null {
  if (!raw) return null;
  const bytes = base64urlDecode(raw);
  if (!bytes) throw new ApiError(400, "cursor inválido");
  try {
    return JSON.parse(new TextDecoder().decode(bytes)) as T;
  } catch {
    throw new ApiError(400, "cursor inválido");
  }
}

export function pageLimit(url: URL, dflt = 50, max = 200): number {
  const n = Number(url.searchParams.get("limit") ?? dflt);
  if (!Number.isInteger(n) || n < 1) throw new ApiError(400, "limit inválido");
  return Math.min(n, max);
}

// Devolve { data, next_cursor } a partir de uma consulta com LIMIT n+1.
export function page<T>(rows: T[], limit: number, cursorOf: (last: T) => Record<string, string | number>) {
  const hasMore = rows.length > limit;
  const data = hasMore ? rows.slice(0, limit) : rows;
  const last = data[data.length - 1];
  return { data, next_cursor: hasMore && last ? encodeCursor(cursorOf(last)) : null };
}

const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$|^localhost$/;
export function validHostname(h: unknown): h is string {
  return typeof h === "string" && (HOSTNAME_RE.test(h.toLowerCase()) || /^localhost(:\d+)?$/.test(h));
}

export function validOrigin(o: unknown): o is string {
  if (o === "demo") return true;
  if (typeof o !== "string") return false;
  try {
    const u = new URL(o);
    return (u.protocol === "https:" || u.protocol === "http:") && u.pathname === "/";
  } catch {
    return false;
  }
}
