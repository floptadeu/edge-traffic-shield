// API de gestão: autenticação com hash, paginação por cursor, links HMAC com TTL,
// versões de ruleset com rollback e propagação <= 5 s sem deploy.
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { api, CONN, createTenant, debugOf, evalHeader, sleep, visit } from "./e2e";
import { chromeHeaders } from "./helpers";

describe("autenticação", () => {
  it("sem chave 401; chave inválida 401; admin ok", async () => {
    expect((await api("/v1/me", { key: null })).status).toBe(401);
    expect((await api("/v1/me", { key: "ets_abcdefgh_naoexiste00000000000000" })).status).toBe(401);
    expect((await api("/v1/me", { key: "qualquer-coisa" })).status).toBe(401);
    const me = (await (await api("/v1/me")).json()) as { principal: { role: string } };
    expect(me.principal.role).toBe("admin");
  });

  it("chave do tenant é guardada só como hash e pode ser revogada", async () => {
    const t = await createTenant();
    const secret = t.apiKey.split("_")[2]!;
    const rows = (await env.DB.prepare("SELECT key_id, key_hash FROM api_keys WHERE tenant_id = ?").bind(t.id).all<{ key_id: string; key_hash: string }>()).results;
    expect(rows).toHaveLength(1);
    expect(rows[0]!.key_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(rows[0]!.key_hash).not.toContain(secret);
    const me = (await (await api("/v1/me", { key: t.apiKey })).json()) as { principal: { role: string; tenantId: string } };
    expect(me.principal).toMatchObject({ role: "tenant", tenantId: t.id });
    // nova chave + revogação da antiga
    const created = (await (await api(`/v1/tenants/${t.id}/keys`, { method: "POST", body: {}, key: t.apiKey })).json()) as { api_key: string };
    expect((await api(`/v1/tenants/${t.id}/keys/${rows[0]!.key_id}`, { method: "DELETE", key: created.api_key })).status).toBe(200);
    expect((await api("/v1/me", { key: t.apiKey })).status).toBe(401);
    expect((await api("/v1/me", { key: created.api_key })).status).toBe(200);
  });
});

describe("tenants e domínios", () => {
  it("cria tenant, valida entrada e lista com cursor", async () => {
    expect((await api("/v1/tenants", { body: { id: "Maiusculo", name: "x", origin: "demo" } })).status).toBe(400);
    expect((await api("/v1/tenants", { body: { id: "ok-1", name: "x", origin: "ftp://nada" } })).status).toBe(400);
    const ids = ["pag-a", "pag-b", "pag-c"];
    for (const id of ids) expect((await api("/v1/tenants", { body: { id, name: id, origin: "https://origem.exemplo/" } })).status).toBe(201);
    expect((await api("/v1/tenants", { body: { id: "pag-a", name: "dup", origin: "demo" } })).status).toBe(409);
    // Percorre todas as páginas de 2 em 2: sem repetir, sem pular, em ordem.
    const all: string[] = [];
    let cursor: string | null = null;
    let pages = 0;
    do {
      const res = await api(`/v1/tenants?limit=2${cursor ? `&cursor=${cursor}` : ""}`);
      const j = (await res.json()) as { data: Array<{ id: string }>; next_cursor: string | null };
      expect(j.data.length).toBeLessThanOrEqual(2);
      all.push(...j.data.map((t) => t.id));
      cursor = j.next_cursor;
      pages++;
    } while (cursor);
    expect(pages).toBeGreaterThanOrEqual(2);
    expect(new Set(all).size).toBe(all.length);
    expect(all.filter((id) => id.startsWith("pag-"))).toEqual(ids);
    expect((await api("/v1/tenants?cursor=%%%")).status).toBe(400);
  });

  it("domínio: registra, compila no KV, devolve instrução de CNAME, lista e remove", async () => {
    const t = await createTenant();
    const res = await api(`/v1/tenants/${t.id}/domains`, { body: { hostname: "Loja.Exemplo.com" }, key: t.apiKey });
    expect(res.status).toBe(201);
    const j = (await res.json()) as { domain: { hostname: string; status: string; dns: { type: string } } };
    expect(j.domain.hostname).toBe("loja.exemplo.com");
    expect(j.domain.status).toBe("manual"); // sem CF_API_TOKEN nos testes
    expect(j.domain.dns.type).toBe("CNAME");
    expect(await env.CONFIG_KV.get("host:loja.exemplo.com", "json")).toMatchObject({ tenantId: t.id, origin: "demo" });
    expect((await api(`/v1/tenants/${t.id}/domains`, { body: { hostname: "inv alido" }, key: t.apiKey })).status).toBe(400);
    const list = (await (await api(`/v1/tenants/${t.id}/domains`, { key: t.apiKey })).json()) as { data: Array<{ hostname: string }> };
    expect(list.data.map((d) => d.hostname).sort()).toEqual(["loja.exemplo.com", t.hostname].sort());
    expect((await api(`/v1/tenants/${t.id}/domains/loja.exemplo.com`, { method: "DELETE", key: t.apiKey })).status).toBe(200);
    expect(await env.CONFIG_KV.get("host:loja.exemplo.com")).toBeNull();
  });

  it("PATCH de origem recompila os hostnames", async () => {
    const t = await createTenant();
    expect((await api(`/v1/tenants/${t.id}`, { method: "PATCH", body: { origin: "https://nova.exemplo/" }, key: t.apiKey })).status).toBe(200);
    expect(await env.CONFIG_KV.get(`host:${t.hostname}`, "json")).toMatchObject({ origin: "https://nova.exemplo/" });
  });
});

describe("ruleset: versões, rollback e propagação", () => {
  it("PUT valida, versiona; rollback move o ponteiro; versões listam com cursor", async () => {
    const t = await createTenant();
    const bad = await api(`/v1/tenants/${t.id}/ruleset`, { method: "PUT", body: { mode: "talvez", weights: { xpto: 1 }, thresholds: { block: 10, decoy: 50 } }, key: t.apiKey });
    expect(bad.status).toBe(400);
    const errs = ((await bad.json()) as { details: string[] }).details;
    expect(errs.join(" ")).toMatch(/mode/);
    expect(errs.join(" ")).toMatch(/weights.xpto/);
    expect(errs.join(" ")).toMatch(/thresholds/);

    const v2 = await api(`/v1/tenants/${t.id}/ruleset`, { method: "PUT", body: { ruleset: { mode: "enforce" }, comment: "liga enforce" }, key: t.apiKey });
    expect(v2.status).toBe(201);
    expect(((await v2.json()) as { version: number }).version).toBe(2);
    const v3 = await api(`/v1/tenants/${t.id}/ruleset`, { method: "PUT", body: { mode: "enforce", weights: { asn: 50 } }, key: t.apiKey });
    expect(((await v3.json()) as { version: number }).version).toBe(3);

    const cur = (await (await api(`/v1/tenants/${t.id}/ruleset`, { key: t.apiKey })).json()) as { version: number; ruleset: { weights: { asn: number } } };
    expect(cur.version).toBe(3);
    expect(cur.ruleset.weights.asn).toBe(50);

    const rb = await api(`/v1/tenants/${t.id}/ruleset/rollback`, { method: "POST", body: {}, key: t.apiKey });
    expect(rb.status).toBe(200);
    expect((await rb.json()) as object).toMatchObject({ version: 2, rolled_back_from: 3 });
    expect(await env.CONFIG_KV.get(`rsptr:${t.id}`, "json")).toEqual({ version: 2 });
    const rb1 = await api(`/v1/tenants/${t.id}/ruleset/rollback`, { method: "POST", body: { version: 1 }, key: t.apiKey });
    expect(((await rb1.json()) as { version: number }).version).toBe(1);
    expect((await api(`/v1/tenants/${t.id}/ruleset/rollback`, { method: "POST", body: { version: 99 }, key: t.apiKey })).status).toBe(404);

    const list = (await (await api(`/v1/tenants/${t.id}/ruleset/versions?limit=2`, { key: t.apiKey })).json()) as { active_version: number; data: Array<{ version: number; active: boolean }>; next_cursor: string };
    expect(list.active_version).toBe(1);
    expect(list.data.map((v) => v.version)).toEqual([3, 2]);
    const rest = (await (await api(`/v1/tenants/${t.id}/ruleset/versions?limit=2&cursor=${list.next_cursor}`, { key: t.apiKey })).json()) as { data: Array<{ version: number; active: boolean }> };
    expect(rest.data).toEqual([expect.objectContaining({ version: 1, active: true })]);
    const one = (await (await api(`/v1/tenants/${t.id}/ruleset/versions/3`, { key: t.apiKey })).json()) as { ruleset: { weights: { asn: number } } };
    expect(one.ruleset.weights.asn).toBe(50);
  });

  it("publicar propaga para o hot path em <= 5 s, sem deploy", async () => {
    const t = await createTenant({ ruleset: { mode: "monitor" } });
    const ctx = await evalHeader(CONN.awsTool);
    const headers = { "user-agent": "curl/8.4.0", "x-eval-context": ctx };
    expect(debugOf(await visit(t.hostname, "/landing", headers)).applied).toBe("ALLOW");

    const published = Date.now();
    expect((await api(`/v1/tenants/${t.id}/ruleset`, { method: "PUT", body: { mode: "enforce" }, key: t.apiKey })).status).toBe(201);
    let applied = "";
    while (Date.now() - published < 5000) {
      const d = debugOf(await visit(t.hostname, "/landing", headers));
      if (d.rs === "v2") {
        applied = d.applied!;
        break;
      }
      await sleep(250);
    }
    const elapsed = Date.now() - published;
    expect(applied).toBe("DECOY");
    expect(elapsed).toBeLessThanOrEqual(5000);

    // rollback também propaga
    const rolled = Date.now();
    await api(`/v1/tenants/${t.id}/ruleset/rollback`, { method: "POST", body: {}, key: t.apiKey });
    let back = false;
    while (Date.now() - rolled < 5000) {
      if (debugOf(await visit(t.hostname, "/landing", headers)).rs === "v1") {
        back = true;
        break;
      }
      await sleep(250);
    }
    expect(back).toBe(true);
  }, 20_000);
});

describe("events, stats e links", () => {
  async function seedEvents(tenantId: string, n: number): Promise<void> {
    const stmts = [];
    for (let i = 0; i < n; i++) {
      stmts.push(
        env.DB.prepare("INSERT INTO events (tenant_id, ts, host, path, ip_hash, asn, country, colo, verdict, applied, score, signals) VALUES (?, ?, 'h', '/', 'x', 1, 'BR', 'GRU', ?, 'ALLOW', ?, '')").bind(
          tenantId,
          1_700_000_000_000 + Math.floor(i / 2) * 1000, // pares de eventos com o mesmo ts: testa o desempate por id
          i % 3 === 0 ? "BLOCK" : "ALLOW",
          i,
        ),
      );
      stmts.push(env.DB.prepare("INSERT INTO stats_minute (tenant_id, minute, verdict, n, score_sum) VALUES (?, ?, ?, 1, ?) ON CONFLICT DO UPDATE SET n = n + 1").bind(tenantId, Math.floor((1_700_000_000_000 + i * 1000) / 60_000), i % 3 === 0 ? "BLOCK" : "ALLOW", i));
    }
    await env.DB.batch(stmts);
  }

  it("events pagina por cursor (ts, id) sem repetir nem pular, com filtro por veredito", async () => {
    const t = await createTenant();
    await seedEvents(t.id, 7);
    const seen: number[] = [];
    let cursor: string | null = null;
    let pages = 0;
    do {
      const res = await api(`/v1/tenants/${t.id}/events?limit=3${cursor ? `&cursor=${cursor}` : ""}`, { key: t.apiKey });
      const j = (await res.json()) as { data: Array<{ id: number; ts: number }>; next_cursor: string | null };
      seen.push(...j.data.map((e) => e.id));
      cursor = j.next_cursor;
      pages++;
    } while (cursor);
    expect(pages).toBe(3);
    expect(new Set(seen).size).toBe(7);
    expect(seen).toEqual([...seen].sort((a, b) => b - a)); // ordem decrescente estável
    const blocks = (await (await api(`/v1/tenants/${t.id}/events?verdict=BLOCK`, { key: t.apiKey })).json()) as { data: Array<{ verdict: string }> };
    expect(blocks.data.length).toBe(3);
    expect((await api(`/v1/tenants/${t.id}/events?verdict=NOPE`, { key: t.apiKey })).status).toBe(400);
  });

  it("stats agrega por minuto e por hora", async () => {
    const t = await createTenant();
    await seedEvents(t.id, 7);
    const s = (await (await api(`/v1/tenants/${t.id}/stats?from=1700000000000&to=1700000100000`, { key: t.apiKey })).json()) as { totals: Record<string, number>; buckets: unknown[] };
    expect(s.totals.total).toBe(7);
    expect(s.totals.BLOCK).toBe(3);
    const h = (await (await api(`/v1/tenants/${t.id}/stats?from=1700000000000&to=1700000100000&granularity=hour`, { key: t.apiKey })).json()) as { buckets: unknown[] };
    expect(h.buckets.length).toBe(1);
  });

  it("links HMAC: abre sem chave até expirar; assinatura adulterada ou alvo de outro recurso falha", async () => {
    const t = await createTenant();
    const res = await api(`/v1/tenants/${t.id}/links`, { body: { target: `/v1/tenants/${t.id}/stats`, ttl: 2 }, key: t.apiKey });
    expect(res.status).toBe(201);
    const { url } = (await res.json()) as { url: string };
    const { SELF } = await import("cloudflare:test");
    expect((await SELF.fetch(url)).status).toBe(200);
    expect((await SELF.fetch(url.replace(/sig=.{5}/, "sig=AAAAA"))).status).toBe(401);
    expect((await SELF.fetch(url.replace("/stats", "/events"))).status).toBe(401);
    expect([401, 405]).toContain((await SELF.fetch(url, { method: "DELETE" })).status); // nunca autoriza escrita
    await sleep(2100);
    expect((await SELF.fetch(url)).status).toBe(401);
    expect((await api(`/v1/tenants/${t.id}/links`, { body: { target: "/v1/tenants/outro/stats" }, key: t.apiKey })).status).toBe(400);
  }, 10_000);

  it("eventos reais chegam ao D1 via Queue e aparecem em /events e /stats", async () => {
    const t = await createTenant({ ruleset: { mode: "enforce" } });
    await visit(t.hostname, "/landing", { "user-agent": "curl/8.4.0", "x-eval-context": await evalHeader(CONN.awsTool) });
    await visit(t.hostname, "/landing", chromeHeaders({ "x-eval-context": await evalHeader(CONN.humanBR) }));
    await visit(t.hostname, "/landing", chromeHeaders({ "x-eval-context": await evalHeader(CONN.humanBR) }));

    // Captura o que os shards mandariam para a Queue e força o flush de todos.
    const { runInDurableObject, listDurableObjectIds, createMessageBatch, getQueueResult, createExecutionContext } = await import("cloudflare:test");
    const { default: worker } = await import("../src/index");
    const sent: unknown[] = [];
    const origSend = env.EVENTS_QUEUE.send.bind(env.EVENTS_QUEUE);
    env.EVENTS_QUEUE.send = (async (m: unknown) => { sent.push(m); }) as never;
    try {
      for (const id of await listDurableObjectIds(env.SHIELD_SHARD)) {
        await runInDurableObject(env.SHIELD_SHARD.get(id), async (inst) => { await (inst as unknown as { flush(): Promise<void> }).flush(); });
      }
    } finally {
      env.EVENTS_QUEUE.send = origSend as never;
    }
    const mine = sent.filter((m) => (m as { tenantId: string }).tenantId === t.id);
    expect(mine.length).toBeGreaterThan(0);

    const batch = createMessageBatch("ets-events", mine.map((body, i) => ({ id: `m${i}`, timestamp: new Date(), body, attempts: 1 })));
    const ctx = createExecutionContext();
    await worker.queue!(batch as never, env as never, ctx);
    expect((await getQueueResult(batch, ctx)).explicitAcks.length).toBe(mine.length);

    const ev = (await (await api(`/v1/tenants/${t.id}/events`, { key: t.apiKey })).json()) as { data: Array<{ verdict: string; applied: string; ip_hash: string }> };
    expect(ev.data.some((e) => e.verdict === "DECOY" && e.applied === "DECOY")).toBe(true);
    expect(ev.data.every((e) => !/\d+\.\d+\.\d+\.\d+/.test(e.ip_hash))).toBe(true); // IP nunca em claro
    const st = (await (await api(`/v1/tenants/${t.id}/stats`, { key: t.apiKey })).json()) as { totals: { total: number; DECOY: number } };
    expect(st.totals.total).toBe(3);
    expect(st.totals.DECOY).toBe(1);
  });
});
