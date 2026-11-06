// Helpers de ponta a ponta: sobem tenant/domínio pela API e batem no Worker.
import { SELF } from "cloudflare:test";
import type { Ruleset } from "../src/shield/ruleset";
import { chromeHeaders, nowSec, signEvalContext } from "./helpers";

export const ADMIN_KEY = "ets_admin_test_key"; // vitest.config.ts

export async function api(path: string, init: { method?: string; body?: unknown; key?: string | null } = {}): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (init.key !== null) headers.authorization = `Bearer ${init.key ?? ADMIN_KEY}`;
  return SELF.fetch(`https://platform.test/__ets/api${path}`, {
    method: init.method ?? (init.body ? "POST" : "GET"),
    headers,
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
}

export interface TenantSetup {
  id: string;
  hostname: string;
  apiKey: string;
}

let seq = 0;
export async function createTenant(opts: { ruleset?: Partial<Ruleset>; origin?: string; id?: string } = {}): Promise<TenantSetup> {
  const id = opts.id ?? `t${Date.now().toString(36)}${(seq++).toString(36)}`;
  const hostname = `${id}.cliente.test`;
  const res = await api("/v1/tenants", { body: { id, name: `Tenant ${id}`, origin: opts.origin ?? "demo", ruleset: opts.ruleset ?? {} } });
  if (res.status !== 201) throw new Error(`createTenant: ${res.status} ${await res.text()}`);
  const j = (await res.json()) as { api_key: string };
  const d = await api(`/v1/tenants/${id}/domains`, { body: { hostname }, key: j.api_key });
  if (d.status !== 201) throw new Error(`domain: ${d.status} ${await d.text()}`);
  return { id, hostname, apiKey: j.api_key };
}

export function visit(hostname: string, path = "/landing", headers: Headers | Record<string, string> = chromeHeaders(), init: RequestInit = {}): Promise<Response> {
  return SELF.fetch(`https://${hostname}${path}`, { headers, ...init });
}

export function debugOf(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (res.headers.get("x-shield-debug") ?? "").split("; ")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i)] = part.slice(i + 1);
  }
  return out;
}

// Conexões prontas para o X-Eval-Context.
export const CONN = {
  humanBR: { ip: "177.10.20.30", asn: 28573, asOrganization: "Claro", country: "BR", tlsVersion: "TLSv1.3", tlsCipher: "AEAD-AES128-GCM-SHA256", tlsClientHelloLength: 1780, httpProtocol: "HTTP/2" },
  aws: { ip: "3.120.10.10", asn: 16509, asOrganization: "Amazon", country: "US", tlsVersion: "TLSv1.3", tlsCipher: "AEAD-AES128-GCM-SHA256", tlsClientHelloLength: 1780, httpProtocol: "HTTP/2" },
  awsTool: { ip: "3.120.10.11", asn: 16509, asOrganization: "Amazon", country: "US", tlsVersion: "TLSv1.2", tlsCipher: "ECDHE-RSA-AES128-GCM-SHA256", tlsClientHelloLength: 300, httpProtocol: "HTTP/1.1" },
};

export async function evalHeader(conn: Record<string, unknown>, over: Record<string, unknown> = {}): Promise<string> {
  return signEvalContext({ ...conn, ...over, iat: nowSec() });
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
