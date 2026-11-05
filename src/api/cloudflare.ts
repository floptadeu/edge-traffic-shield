// Cliente mínimo da API de Custom Hostnames (Cloudflare for SaaS).
// Sem CF_API_TOKEN/CF_ZONE_ID configurados a plataforma funciona em modo
// "manual": o domínio é registrado e o cliente aponta o CNAME, mas o
// certificado/validação precisa ser criado no dashboard.

import type { Env } from "../env";

export interface CustomHostnameInfo {
  id: string;
  status: string;
  ssl_status?: string;
  ownership_verification?: unknown;
  ssl_validation_records?: unknown;
}

const API = "https://api.cloudflare.com/client/v4";

export function saasConfigured(env: Env): boolean {
  return Boolean(env.CF_API_TOKEN && env.CF_ZONE_ID);
}

async function call<T>(env: Env, method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${API}/zones/${env.CF_ZONE_ID}${path}`, {
    method,
    headers: { authorization: `Bearer ${env.CF_API_TOKEN}`, "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const j = (await res.json()) as { success: boolean; result: T; errors?: Array<{ message: string }> };
  if (!j.success) throw new Error(`cloudflare: ${j.errors?.map((e) => e.message).join("; ") ?? res.status}`);
  return j.result;
}

function pick(r: Record<string, unknown>): CustomHostnameInfo {
  const ssl = (r.ssl ?? {}) as Record<string, unknown>;
  return {
    id: String(r.id),
    status: String(r.status),
    ssl_status: typeof ssl.status === "string" ? ssl.status : undefined,
    ownership_verification: r.ownership_verification,
    ssl_validation_records: ssl.validation_records,
  };
}

export async function createCustomHostname(env: Env, hostname: string): Promise<CustomHostnameInfo> {
  const r = await call<Record<string, unknown>>(env, "POST", "/custom_hostnames", {
    hostname,
    ssl: { method: "http", type: "dv", settings: { min_tls_version: "1.2" } },
  });
  return pick(r);
}

export async function getCustomHostname(env: Env, id: string): Promise<CustomHostnameInfo> {
  return pick(await call<Record<string, unknown>>(env, "GET", `/custom_hostnames/${id}`));
}

export async function deleteCustomHostname(env: Env, id: string): Promise<void> {
  await call(env, "DELETE", `/custom_hostnames/${id}`);
}
