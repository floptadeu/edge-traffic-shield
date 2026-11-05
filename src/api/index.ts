// API de gestão: /__ets/api/v1/...
// Rotas pequenas e explícitas (sem framework): fácil de ler e de alterar ao vivo.

import type { Env } from "../env";
import { DEFAULT_RULESET, validateRuleset, type Ruleset, type Verdict, VERDICTS } from "../shield/ruleset";
import { compileHost, publishRuleset, rollbackRuleset } from "../shield/publish";
import { authenticate, createApiKey, linkSignature, requireAdmin, requireTenant, type Principal } from "./auth";
import { createCustomHostname, deleteCustomHostname, getCustomHostname, saasConfigured } from "./cloudflare";
import { ApiError, decodeCursor, json, page, pageLimit, readJson, validHostname, validOrigin } from "./http";

type Handler = (c: Ctx) => Promise<Response>;
interface Ctx {
  request: Request;
  env: Env;
  url: URL;
  params: Record<string, string>;
  principal: Principal;
}

const routes: Array<[string, RegExp, Handler]> = [];
function route(method: string, pattern: string, h: Handler): void {
  const re = new RegExp("^" + pattern.replace(/:([a-zA-Z]+)/g, "(?<$1>[^/]+)") + "$");
  routes.push([method, re, h]);
}

export async function handleApi(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/__ets\/api/, "");
  try {
    let methodMismatch = false;
    for (const [method, re, h] of routes) {
      const m = re.exec(path);
      if (!m) continue;
      if (method !== request.method) {
        methodMismatch = true;
        continue;
      }
      const principal = await authenticate(request, env, url);
      return await h({ request, env, url, params: (m.groups ?? {}) as Record<string, string>, principal });
    }
    throw new ApiError(methodMismatch ? 405 : 404, methodMismatch ? "método não permitido" : "rota não encontrada");
  } catch (err) {
    if (err instanceof ApiError) return json({ error: err.message, details: err.details }, err.status);
    const msg = err instanceof Error ? err.message : String(err);
    return json({ error: "erro interno", detail: msg }, 500);
  }
}

// ---------------------------------------------------------------- me
route("GET", "/v1/me", async ({ principal }) => json({ principal }));

// ---------------------------------------------------------------- tenants
interface TenantRow {
  id: string;
  name: string;
  origin: string;
  ruleset_version: number;
  created_at: number;
  updated_at: number;
}

route("POST", "/v1/tenants", async ({ request, env, principal }) => {
  requireAdmin(principal);
  const b = await readJson(request);
  const id = typeof b.id === "string" && /^[a-z0-9][a-z0-9-]{1,30}$/.test(b.id) ? b.id : null;
  if (!id) throw new ApiError(400, "id: minúsculas, dígitos e hífen (2-31 chars)");
  if (typeof b.name !== "string" || !b.name) throw new ApiError(400, "name obrigatório");
  if (!validOrigin(b.origin)) throw new ApiError(400, 'origin: URL https://... (raiz) ou "demo"');
  const exists = await env.DB.prepare("SELECT 1 FROM tenants WHERE id = ?").bind(id).first();
  if (exists) throw new ApiError(409, "tenant já existe");
  const now = Date.now();
  await env.DB.prepare("INSERT INTO tenants (id, name, origin, ruleset_version, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?)")
    .bind(id, b.name, b.origin, now, now)
    .run();
  // Ruleset inicial: defaults em modo monitor (ou o enviado no corpo).
  const initial = b.ruleset === undefined ? { ok: true as const, ruleset: DEFAULT_RULESET } : validateRuleset(b.ruleset);
  if (!initial.ok) throw new ApiError(400, "ruleset inválido", initial.errors);
  const version = await publishRuleset(env, id, initial.ruleset, "inicial");
  const key = await createApiKey(env, id, "tenant");
  return json({ tenant: await getTenant(env, id), ruleset_version: version, api_key: key.apiKey, key_id: key.keyId }, 201);
});

route("GET", "/v1/tenants", async ({ env, url, principal }) => {
  requireAdmin(principal);
  const limit = pageLimit(url);
  const cur = decodeCursor<{ id: string }>(url.searchParams.get("cursor"));
  const rows = (
    await env.DB.prepare("SELECT * FROM tenants WHERE id > ? ORDER BY id LIMIT ?")
      .bind(cur?.id ?? "", limit + 1)
      .all<TenantRow>()
  ).results;
  return json(page(rows, limit, (t) => ({ id: t.id })));
});

route("GET", "/v1/tenants/:id", async ({ env, params, principal }) => {
  requireTenant(principal, params.id!);
  return json({ tenant: await getTenant(env, params.id!) });
});

route("PATCH", "/v1/tenants/:id", async ({ request, env, params, principal }) => {
  requireTenant(principal, params.id!, { write: true });
  const t = await getTenant(env, params.id!);
  const b = await readJson(request);
  const name = typeof b.name === "string" && b.name ? b.name : t.name;
  if (b.origin !== undefined && !validOrigin(b.origin)) throw new ApiError(400, "origin inválida");
  const origin = (b.origin as string | undefined) ?? t.origin;
  await env.DB.prepare("UPDATE tenants SET name = ?, origin = ?, updated_at = ? WHERE id = ?").bind(name, origin, Date.now(), t.id).run();
  // Recompila todos os hostnames do tenant no KV (origem pode ter mudado).
  const hosts = (await env.DB.prepare("SELECT hostname FROM domains WHERE tenant_id = ?").bind(t.id).all<{ hostname: string }>()).results;
  for (const h of hosts) await compileHost(env, h.hostname, { id: t.id, origin });
  return json({ tenant: await getTenant(env, t.id) });
});

route("POST", "/v1/tenants/:id/keys", async ({ env, params, principal }) => {
  requireTenant(principal, params.id!, { write: true });
  await getTenant(env, params.id!);
  const key = await createApiKey(env, params.id!, "tenant");
  return json({ key_id: key.keyId, api_key: key.apiKey }, 201);
});

route("DELETE", "/v1/tenants/:id/keys/:keyId", async ({ env, params, principal }) => {
  requireTenant(principal, params.id!, { write: true });
  const r = await env.DB.prepare("UPDATE api_keys SET revoked_at = ? WHERE key_id = ? AND tenant_id = ? AND revoked_at IS NULL")
    .bind(Date.now(), params.keyId, params.id)
    .run();
  if (!r.meta.changes) throw new ApiError(404, "chave não encontrada");
  return json({ revoked: params.keyId });
});

async function getTenant(env: Env, id: string): Promise<TenantRow> {
  const t = await env.DB.prepare("SELECT * FROM tenants WHERE id = ?").bind(id).first<TenantRow>();
  if (!t) throw new ApiError(404, "tenant não encontrado");
  return t;
}

// ---------------------------------------------------------------- domains
interface DomainRow {
  hostname: string;
  tenant_id: string;
  status: string;
  cf_hostname_id: string | null;
  verification: string | null;
  created_at: number;
  updated_at: number;
}

function domainView(d: DomainRow, env: Env) {
  return {
    hostname: d.hostname,
    status: d.status,
    cf_hostname_id: d.cf_hostname_id,
    verification: d.verification ? JSON.parse(d.verification) : null,
    dns: { type: "CNAME", name: d.hostname, target: env.FALLBACK_ORIGIN || "<FALLBACK_ORIGIN não configurado>" },
    created_at: d.created_at,
    updated_at: d.updated_at,
  };
}

route("POST", "/v1/tenants/:id/domains", async ({ request, env, params, principal }) => {
  requireTenant(principal, params.id!, { write: true });
  const t = await getTenant(env, params.id!);
  const b = await readJson(request);
  if (!validHostname(b.hostname)) throw new ApiError(400, "hostname inválido");
  const hostname = b.hostname.toLowerCase();
  const taken = await env.DB.prepare("SELECT tenant_id FROM domains WHERE hostname = ?").bind(hostname).first<{ tenant_id: string }>();
  if (taken) throw new ApiError(409, "hostname já registrado"); // em qualquer tenant: isolamento

  let status = "manual";
  let cfId: string | null = null;
  let verification: string | null = null;
  if (saasConfigured(env) && hostname !== "localhost") {
    try {
      const ch = await createCustomHostname(env, hostname);
      status = ch.status;
      cfId = ch.id;
      verification = JSON.stringify({ ownership_verification: ch.ownership_verification, ssl_validation_records: ch.ssl_validation_records, ssl_status: ch.ssl_status });
    } catch (err) {
      status = "error";
      verification = JSON.stringify({ error: err instanceof Error ? err.message : String(err) });
    }
  }
  const now = Date.now();
  await env.DB.prepare("INSERT INTO domains (hostname, tenant_id, status, cf_hostname_id, verification, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .bind(hostname, t.id, status, cfId, verification, now, now)
    .run();
  await compileHost(env, hostname, { id: t.id, origin: t.origin }); // hot path pronto
  const d = await env.DB.prepare("SELECT * FROM domains WHERE hostname = ?").bind(hostname).first<DomainRow>();
  return json({ domain: domainView(d!, env) }, 201);
});

route("GET", "/v1/tenants/:id/domains", async ({ env, url, params, principal }) => {
  requireTenant(principal, params.id!);
  const limit = pageLimit(url);
  const cur = decodeCursor<{ hostname: string }>(url.searchParams.get("cursor"));
  const rows = (
    await env.DB.prepare("SELECT * FROM domains WHERE tenant_id = ? AND hostname > ? ORDER BY hostname LIMIT ?")
      .bind(params.id, cur?.hostname ?? "", limit + 1)
      .all<DomainRow>()
  ).results;
  const p = page(rows, limit, (d) => ({ hostname: d.hostname }));
  return json({ data: p.data.map((d) => domainView(d, env)), next_cursor: p.next_cursor });
});

route("GET", "/v1/tenants/:id/domains/:hostname", async ({ env, params, principal }) => {
  requireTenant(principal, params.id!);
  let d = await env.DB.prepare("SELECT * FROM domains WHERE hostname = ? AND tenant_id = ?").bind(params.hostname!.toLowerCase(), params.id).first<DomainRow>();
  if (!d) throw new ApiError(404, "domínio não encontrado");
  // Atualiza o status na Cloudflare (validação de DNS/certificado é assíncrona).
  if (d.cf_hostname_id && saasConfigured(env)) {
    try {
      const ch = await getCustomHostname(env, d.cf_hostname_id);
      const verification = JSON.stringify({ ownership_verification: ch.ownership_verification, ssl_validation_records: ch.ssl_validation_records, ssl_status: ch.ssl_status });
      await env.DB.prepare("UPDATE domains SET status = ?, verification = ?, updated_at = ? WHERE hostname = ?").bind(ch.status, verification, Date.now(), d.hostname).run();
      d = { ...d, status: ch.status, verification };
    } catch {
      // mantém o último status conhecido
    }
  }
  return json({ domain: domainView(d, env) });
});

route("DELETE", "/v1/tenants/:id/domains/:hostname", async ({ env, params, principal }) => {
  requireTenant(principal, params.id!, { write: true });
  const hostname = params.hostname!.toLowerCase();
  const d = await env.DB.prepare("SELECT * FROM domains WHERE hostname = ? AND tenant_id = ?").bind(hostname, params.id).first<DomainRow>();
  if (!d) throw new ApiError(404, "domínio não encontrado");
  if (d.cf_hostname_id && saasConfigured(env)) await deleteCustomHostname(env, d.cf_hostname_id).catch(() => {});
  await env.DB.prepare("DELETE FROM domains WHERE hostname = ?").bind(hostname).run();
  await env.CONFIG_KV.delete(`host:${hostname}`);
  return json({ deleted: hostname });
});

// ---------------------------------------------------------------- ruleset
async function currentRuleset(env: Env, tenantId: string): Promise<{ version: number; ruleset: Ruleset; comment: string | null; created_at: number }> {
  const t = await getTenant(env, tenantId);
  const row = await env.DB.prepare("SELECT body, comment, created_at FROM ruleset_versions WHERE tenant_id = ? AND version = ?")
    .bind(tenantId, t.ruleset_version)
    .first<{ body: string; comment: string | null; created_at: number }>();
  if (!row) return { version: 0, ruleset: DEFAULT_RULESET, comment: null, created_at: 0 };
  return { version: t.ruleset_version, ruleset: JSON.parse(row.body) as Ruleset, comment: row.comment, created_at: row.created_at };
}

route("GET", "/v1/tenants/:id/ruleset", async ({ env, params, principal }) => {
  requireTenant(principal, params.id!);
  return json(await currentRuleset(env, params.id!));
});

route("PUT", "/v1/tenants/:id/ruleset", async ({ request, env, params, principal }) => {
  requireTenant(principal, params.id!, { write: true });
  await getTenant(env, params.id!);
  const b = await readJson(request);
  // Aceita { ruleset, comment } ou o ruleset direto.
  const input = "ruleset" in b && typeof b.ruleset === "object" ? b.ruleset : b;
  const comment = typeof b.comment === "string" ? b.comment : null;
  const v = validateRuleset(input);
  if (!v.ok) throw new ApiError(400, "ruleset inválido", v.errors);
  const version = await publishRuleset(env, params.id!, v.ruleset, comment);
  return json({ version, ruleset: v.ruleset }, 201);
});

route("GET", "/v1/tenants/:id/ruleset/versions", async ({ env, url, params, principal }) => {
  requireTenant(principal, params.id!);
  const t = await getTenant(env, params.id!);
  const limit = pageLimit(url);
  const cur = decodeCursor<{ version: number }>(url.searchParams.get("cursor"));
  const rows = (
    await env.DB.prepare("SELECT version, comment, created_at FROM ruleset_versions WHERE tenant_id = ? AND version < ? ORDER BY version DESC LIMIT ?")
      .bind(t.id, cur?.version ?? Number.MAX_SAFE_INTEGER, limit + 1)
      .all<{ version: number; comment: string | null; created_at: number }>()
  ).results;
  const p = page(rows, limit, (r) => ({ version: r.version }));
  return json({ active_version: t.ruleset_version, data: p.data.map((r) => ({ ...r, active: r.version === t.ruleset_version })), next_cursor: p.next_cursor });
});

route("GET", "/v1/tenants/:id/ruleset/versions/:version", async ({ env, params, principal }) => {
  requireTenant(principal, params.id!);
  const row = await env.DB.prepare("SELECT version, body, comment, created_at FROM ruleset_versions WHERE tenant_id = ? AND version = ?")
    .bind(params.id, Number(params.version))
    .first<{ version: number; body: string; comment: string | null; created_at: number }>();
  if (!row) throw new ApiError(404, "versão não encontrada");
  return json({ version: row.version, comment: row.comment, created_at: row.created_at, ruleset: JSON.parse(row.body) });
});

route("POST", "/v1/tenants/:id/ruleset/rollback", async ({ request, env, params, principal }) => {
  requireTenant(principal, params.id!, { write: true });
  const t = await getTenant(env, params.id!);
  const b = request.headers.get("content-length") === "0" || !request.body ? {} : await readJson(request);
  let version = typeof b.version === "number" ? b.version : null;
  if (version === null) {
    // Sem versão explícita: a imediatamente anterior à ativa.
    const prev = await env.DB.prepare("SELECT MAX(version) AS v FROM ruleset_versions WHERE tenant_id = ? AND version < ?").bind(t.id, t.ruleset_version).first<{ v: number | null }>();
    if (!prev?.v) throw new ApiError(409, "não há versão anterior");
    version = prev.v;
  }
  const rs = await rollbackRuleset(env, t.id, version);
  if (!rs) throw new ApiError(404, "versão não encontrada");
  return json({ version, ruleset: rs, rolled_back_from: t.ruleset_version });
});

// ---------------------------------------------------------------- events
route("GET", "/v1/tenants/:id/events", async ({ env, url, params, principal }) => {
  requireTenant(principal, params.id!);
  const limit = pageLimit(url);
  const cur = decodeCursor<{ ts: number; id: number }>(url.searchParams.get("cursor"));
  const verdict = url.searchParams.get("verdict");
  if (verdict && !VERDICTS.includes(verdict as Verdict)) throw new ApiError(400, "verdict inválido");
  const since = Number(url.searchParams.get("since") ?? 0);
  const where = ["tenant_id = ?", "ts >= ?"];
  const binds: unknown[] = [params.id, since];
  if (cur) {
    where.push("(ts < ? OR (ts = ? AND id < ?))");
    binds.push(cur.ts, cur.ts, cur.id);
  }
  if (verdict) {
    where.push("verdict = ?");
    binds.push(verdict);
  }
  binds.push(limit + 1);
  const rows = (
    await env.DB.prepare(`SELECT * FROM events WHERE ${where.join(" AND ")} ORDER BY ts DESC, id DESC LIMIT ?`).bind(...binds).all<{ id: number; ts: number }>()
  ).results;
  return json(page(rows, limit, (e) => ({ ts: e.ts, id: e.id })));
});

// ---------------------------------------------------------------- stats
route("GET", "/v1/tenants/:id/stats", async ({ env, url, params, principal }) => {
  requireTenant(principal, params.id!);
  const nowMin = Math.floor(Date.now() / 60_000);
  const from = Number(url.searchParams.get("from") ?? (nowMin - 60) * 60_000);
  const to = Number(url.searchParams.get("to") ?? Date.now());
  const granularity = url.searchParams.get("granularity") === "hour" ? 60 : 1;
  if (!Number.isFinite(from) || !Number.isFinite(to) || from > to) throw new ApiError(400, "from/to inválidos (epoch ms)");
  const rows = (
    await env.DB.prepare("SELECT minute, verdict, n, score_sum FROM stats_minute WHERE tenant_id = ? AND minute BETWEEN ? AND ? ORDER BY minute")
      .bind(params.id, Math.floor(from / 60_000), Math.floor(to / 60_000))
      .all<{ minute: number; verdict: Verdict; n: number; score_sum: number }>()
  ).results;
  const buckets = new Map<number, Record<string, number>>();
  const totals: Record<string, number> = { ALLOW: 0, SILENT_VERIFY: 0, DECOY: 0, BLOCK: 0, total: 0, score_sum: 0 };
  for (const r of rows) {
    const t = Math.floor(r.minute / granularity) * granularity * 60_000;
    const b = buckets.get(t) ?? { t, ALLOW: 0, SILENT_VERIFY: 0, DECOY: 0, BLOCK: 0, total: 0, score_sum: 0 };
    b[r.verdict] = (b[r.verdict] ?? 0) + r.n;
    b.total! += r.n;
    b.score_sum! += r.score_sum;
    buckets.set(t, b);
    totals[r.verdict] = (totals[r.verdict] ?? 0) + r.n;
    totals.total! += r.n;
    totals.score_sum! += r.score_sum;
  }
  const withAvg = (b: Record<string, number>) => ({ ...b, avg_score: b.total ? Math.round(b.score_sum! / b.total) : 0 });
  return json({ from, to, granularity: granularity === 60 ? "hour" : "minute", totals: withAvg(totals), buckets: [...buckets.values()].map(withAvg) });
});

// ---------------------------------------------------------------- links (HMAC + TTL)
route("POST", "/v1/tenants/:id/links", async ({ request, env, url, params, principal }) => {
  requireTenant(principal, params.id!, { write: true });
  if (!env.COOKIE_SECRET) throw new ApiError(500, "COOKIE_SECRET não configurado");
  const b = await readJson(request);
  const target = typeof b.target === "string" ? b.target : `/v1/tenants/${params.id}/stats`;
  if (!target.startsWith(`/v1/tenants/${params.id}/`)) throw new ApiError(400, "target precisa ser um recurso deste tenant");
  const ttl = typeof b.ttl === "number" && b.ttl > 0 && b.ttl <= 7 * 86_400 ? Math.floor(b.ttl) : 3600;
  const exp = Math.floor(Date.now() / 1000) + ttl;
  const targetUrl = new URL(`/__ets/api${target}`, url.origin);
  targetUrl.searchParams.set("exp", String(exp));
  targetUrl.searchParams.set("sig", await linkSignature(env.COOKIE_SECRET, targetUrl.pathname, exp));
  return json({ url: targetUrl.toString(), expires_at: exp, ttl }, 201);
});
