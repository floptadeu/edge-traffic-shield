// Config no hot path: hostname -> tenant (KV, fallback D1) e ruleset por
// versão (KV, chave imutável). Tudo com memo no isolate e fail-open.

import type { Env } from "../env";
import { safe, type DegradedLog } from "../lib/failopen";
import { DEFAULT_RULESET, parseStoredRuleset, type Ruleset } from "./ruleset";

export interface TenantHost {
  tenantId: string;
  origin: string; // URL base da origem do cliente ("demo" = origem embutida)
}

const HOST_MEMO_MS = 30_000;
const hostMemo = new Map<string, { value: TenantHost | null; exp: number }>();
const rulesetMemo = new Map<string, Ruleset>(); // `${tenant}:${version}` (imutável)
const knownVersion = new Map<string, number>(); // última versão vista do DO

export function hostKey(hostname: string): string {
  return `host:${hostname.toLowerCase()}`;
}
export function rulesetKey(tenantId: string, version: number): string {
  return `ruleset:${tenantId}:${version}`;
}
export function pointerKey(tenantId: string): string {
  return `rsptr:${tenantId}`;
}

export async function resolveTenant(hostname: string, env: Env, log: DegradedLog): Promise<TenantHost | null> {
  const h = hostname.toLowerCase();
  const m = hostMemo.get(h);
  if (m && m.exp > Date.now()) return m.value;

  let value: TenantHost | null | undefined;
  const fromKv = await safe("kv", env.CONFIG_KV.get(hostKey(h), { type: "json", cacheTtl: 60 }), undefined, log);
  if (fromKv !== undefined) value = (fromKv as TenantHost | null) ?? null;

  if (value === undefined || value === null) {
    // KV falhou ou não tem: D1 é a fonte da verdade.
    const row = await safe(
      "d1",
      env.DB.prepare(
        "SELECT t.id AS tenantId, t.origin AS origin FROM domains d JOIN tenants t ON t.id = d.tenant_id WHERE d.hostname = ?",
      )
        .bind(h)
        .first<{ tenantId: string; origin: string }>(),
      undefined,
      log,
    );
    if (row) value = { tenantId: row.tenantId, origin: row.origin };
    else if (row === null) value = null;
  }

  if (value === undefined) {
    // Tudo falhou: usa o último valor conhecido mesmo vencido (melhor que derrubar o site).
    return m?.value ?? null;
  }
  hostMemo.set(h, { value, exp: Date.now() + HOST_MEMO_MS });
  return value;
}

// Versão a usar no Worker: a última que o DO informou; senão o ponteiro do KV.
export async function loadRuleset(
  tenantId: string,
  env: Env,
  log: DegradedLog,
): Promise<{ version: number; ruleset: Ruleset }> {
  let version = knownVersion.get(tenantId);
  if (version === undefined) {
    const ptr = await safe("kv", env.CONFIG_KV.get(pointerKey(tenantId), { type: "json", cacheTtl: 60 }), null, log);
    version = typeof (ptr as { version?: unknown } | null)?.version === "number" ? (ptr as { version: number }).version : 0;
  }
  if (!version) return { version: 0, ruleset: DEFAULT_RULESET };
  return { version, ruleset: await rulesetByVersion(tenantId, version, env, log) };
}

export async function rulesetByVersion(tenantId: string, version: number, env: Env, log: DegradedLog): Promise<Ruleset> {
  const k = rulesetKey(tenantId, version);
  const m = rulesetMemo.get(k);
  if (m) return m;
  const body = await safe("kv", env.CONFIG_KV.get(k, { cacheTtl: 86_400 }), null, log);
  if (!body) return DEFAULT_RULESET;
  const rs = parseStoredRuleset(body);
  if (rulesetMemo.size > 200) rulesetMemo.clear();
  rulesetMemo.set(k, rs);
  return rs;
}

// Chamado com a versão que o DO devolveu: o próximo request já usa a nova.
export function noteVersion(tenantId: string, version: number): void {
  if (version > 0) knownVersion.set(tenantId, version);
}

// Para testes: limpa memos do isolate.
export function resetTenantMemo(): void {
  hostMemo.clear();
  rulesetMemo.clear();
  knownVersion.clear();
}
