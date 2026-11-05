// Publicação de ruleset sem deploy:
//   1. D1 (fonte da verdade): nova linha imutável em ruleset_versions + ponteiro
//   2. KV: `ruleset:{tenant}:{v}` (imutável) ANTES do ponteiro `rsptr:{tenant}`
//   3. TenantConfig DO: setVersion(v) — é daqui que os shards leem em <= 2 s
// Rollback só move o ponteiro (2 e 3) para uma versão que já existe.

import type { Env } from "../env";
import type { Ruleset } from "../shield/ruleset";
import { pointerKey, rulesetKey } from "../shield/tenant";

export async function publishRuleset(env: Env, tenantId: string, ruleset: Ruleset, comment: string | null): Promise<number> {
  const now = Date.now();
  const row = await env.DB.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM ruleset_versions WHERE tenant_id = ?")
    .bind(tenantId)
    .first<{ v: number }>();
  const version = (row?.v ?? 0) + 1;
  const body = JSON.stringify(ruleset);
  await env.DB.batch([
    env.DB.prepare("INSERT INTO ruleset_versions (tenant_id, version, body, comment, created_at) VALUES (?, ?, ?, ?, ?)").bind(
      tenantId,
      version,
      body,
      comment,
      now,
    ),
    env.DB.prepare("UPDATE tenants SET ruleset_version = ?, updated_at = ? WHERE id = ?").bind(version, now, tenantId),
  ]);
  await activateVersion(env, tenantId, version, body);
  return version;
}

export async function rollbackRuleset(env: Env, tenantId: string, version: number): Promise<Ruleset | null> {
  const row = await env.DB.prepare("SELECT body FROM ruleset_versions WHERE tenant_id = ? AND version = ?")
    .bind(tenantId, version)
    .first<{ body: string }>();
  if (!row) return null;
  await env.DB.prepare("UPDATE tenants SET ruleset_version = ?, updated_at = ? WHERE id = ?").bind(version, Date.now(), tenantId).run();
  await activateVersion(env, tenantId, version, row.body);
  return JSON.parse(row.body) as Ruleset;
}

async function activateVersion(env: Env, tenantId: string, version: number, body: string): Promise<void> {
  // Ordem importa: a chave imutável precisa existir antes de alguém ler o ponteiro.
  await env.CONFIG_KV.put(rulesetKey(tenantId, version), body);
  await env.CONFIG_KV.put(pointerKey(tenantId), JSON.stringify({ version }));
  const cfg = env.TENANT_CONFIG.get(env.TENANT_CONFIG.idFromName(tenantId));
  await cfg.setVersion(version);
}

// Config do hostname compilada para o hot path.
export async function compileHost(env: Env, hostname: string, tenant: { id: string; origin: string }): Promise<void> {
  await env.CONFIG_KV.put(`host:${hostname.toLowerCase()}`, JSON.stringify({ tenantId: tenant.id, origin: tenant.origin }));
}
