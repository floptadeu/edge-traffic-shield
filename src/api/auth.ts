// Autenticação da API.
//   Bearer <ADMIN_API_KEY>            -> admin (cria/lista tenants)
//   Bearer ets_<keyId>_<secret>       -> tenant (escopo = o tenant da chave)
//   ?exp=<epoch>&sig=<hmac>           -> link assinado, só leitura, só aquele path
// Chaves nunca são guardadas em claro: D1 tem sha256(secret).

import type { Env } from "../env";
import { hmacSha256Base64url, randomAlnum, sha256Hex, timingSafeEqual } from "../lib/crypto";
import { ApiError } from "./http";

export type Principal =
  | { role: "admin" }
  | { role: "tenant"; tenantId: string; keyId: string }
  | { role: "link"; tenantId: string };

const enc = new TextEncoder();

function safeEqualStr(a: string, b: string): boolean {
  return timingSafeEqual(enc.encode(a), enc.encode(b));
}

export async function authenticate(request: Request, env: Env, url: URL): Promise<Principal> {
  const auth = request.headers.get("authorization");
  if (auth?.startsWith("Bearer ")) {
    const key = auth.slice(7).trim();
    // Admin: compara hashes para a comparação ser de tamanho fixo e tempo constante.
    if (env.ADMIN_API_KEY && safeEqualStr(await sha256Hex(key), await sha256Hex(env.ADMIN_API_KEY))) return { role: "admin" };
    const m = /^ets_([A-Za-z0-9]{8})_([A-Za-z0-9]{32})$/.exec(key);
    if (m) {
      const row = await env.DB.prepare("SELECT key_hash, tenant_id, role, revoked_at FROM api_keys WHERE key_id = ?")
        .bind(m[1])
        .first<{ key_hash: string; tenant_id: string | null; role: string; revoked_at: number | null }>();
      if (row && !row.revoked_at && safeEqualStr(await sha256Hex(m[2]!), row.key_hash)) {
        if (row.role === "admin") return { role: "admin" };
        if (row.tenant_id) return { role: "tenant", tenantId: row.tenant_id, keyId: m[1]! };
      }
    }
    throw new ApiError(401, "chave inválida");
  }

  // Link assinado (gerado por POST /links)
  const exp = Number(url.searchParams.get("exp"));
  const sig = url.searchParams.get("sig");
  if (sig && Number.isFinite(exp)) {
    if (request.method !== "GET") throw new ApiError(401, "link assinado só permite GET");
    if (exp * 1000 < Date.now()) throw new ApiError(401, "link expirado");
    const tenantId = /^\/__ets\/api\/v1\/tenants\/([^/]+)\//.exec(url.pathname)?.[1];
    if (!tenantId || !env.COOKIE_SECRET) throw new ApiError(401, "link inválido");
    const expected = await linkSignature(env.COOKIE_SECRET, url.pathname, exp);
    if (!safeEqualStr(expected, sig)) throw new ApiError(401, "assinatura inválida");
    return { role: "link", tenantId };
  }

  throw new ApiError(401, "informe Authorization: Bearer <api key>");
}

export function linkSignature(secret: string, pathname: string, exp: number): Promise<string> {
  return hmacSha256Base64url(secret, `GET:${pathname}:${exp}`);
}

// Garante escopo: tenant só enxerga o próprio id. Admin enxerga tudo.
export function requireTenant(p: Principal, tenantId: string, opts: { write?: boolean } = {}): void {
  if (p.role === "admin") return;
  if (p.tenantId !== tenantId) throw new ApiError(404, "tenant não encontrado"); // 404 para não vazar existência
  if (opts.write && p.role === "link") throw new ApiError(403, "link assinado é só leitura");
}

export function requireAdmin(p: Principal): void {
  if (p.role !== "admin") throw new ApiError(403, "requer chave admin");
}

// Gera uma chave nova. O segredo é devolvido UMA vez; só o hash fica no D1.
export async function createApiKey(env: Env, tenantId: string | null, role: "admin" | "tenant"): Promise<{ keyId: string; apiKey: string }> {
  const keyId = randomAlnum(8);
  const secret = randomAlnum(32);
  await env.DB.prepare("INSERT INTO api_keys (key_id, key_hash, tenant_id, role, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(keyId, await sha256Hex(secret), tenantId, role, Date.now())
    .run();
  return { keyId, apiKey: `ets_${keyId}_${secret}` };
}
