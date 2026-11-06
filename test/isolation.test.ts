// Isolamento entre tenants: chave de um não enxerga o outro (API) e o ruleset
// de um não afeta o tráfego do outro (hot path).
import { describe, expect, it } from "vitest";
import { api, CONN, createTenant, debugOf, evalHeader, visit } from "./e2e";
import { chromeHeaders } from "./helpers";

describe("isolamento cross-tenant", () => {
  it("API: chave do tenant A não lê, altera nem registra nada em B", async () => {
    const a = await createTenant();
    const b = await createTenant();
    for (const path of [`/v1/tenants/${b.id}`, `/v1/tenants/${b.id}/ruleset`, `/v1/tenants/${b.id}/events`, `/v1/tenants/${b.id}/stats`, `/v1/tenants/${b.id}/domains`]) {
      const res = await api(path, { key: a.apiKey });
      expect(res.status, path).toBe(404);
    }
    expect((await api(`/v1/tenants/${b.id}/ruleset`, { method: "PUT", body: { mode: "enforce" }, key: a.apiKey })).status).toBe(404);
    expect((await api(`/v1/tenants/${b.id}/links`, { body: { ttl: 60 }, key: a.apiKey })).status).toBe(404);
    // hostname de B não pode ser "roubado" por A
    expect((await api(`/v1/tenants/${a.id}/domains`, { body: { hostname: b.hostname }, key: a.apiKey })).status).toBe(409);
    // tenant não lista tenants nem cria outros
    expect((await api("/v1/tenants", { key: a.apiKey })).status).toBe(403);
    expect((await api("/v1/tenants", { body: { id: "x1", name: "x", origin: "demo" }, key: a.apiKey })).status).toBe(403);
  });

  it("link assinado de A não abre recurso de B", async () => {
    const a = await createTenant();
    const b = await createTenant();
    const link = (await (await api(`/v1/tenants/${a.id}/links`, { body: { target: `/v1/tenants/${a.id}/stats`, ttl: 60 }, key: a.apiKey })).json()) as { url: string };
    const ok = await fetchRaw(link.url);
    expect(ok.status).toBe(200);
    const swapped = link.url.replace(`/tenants/${a.id}/`, `/tenants/${b.id}/`);
    expect((await fetchRaw(swapped)).status).toBe(401);
  });

  it("hot path: mesma requisição, vereditos independentes por tenant", async () => {
    const strict = await createTenant({ ruleset: { mode: "enforce", rules: [{ id: "block-aws", if: { field: "asn", op: "eq", value: 16509 }, verdict: "BLOCK" }] } });
    const lax = await createTenant({ ruleset: { mode: "monitor" } });
    const ctx = await evalHeader(CONN.aws);
    const headers = { "user-agent": "curl/8.4.0", "x-eval-context": ctx };
    const r1 = await visit(strict.hostname, "/landing", headers);
    const r2 = await visit(lax.hostname, "/landing", headers);
    expect(r1.status).toBe(403);
    expect(debugOf(r1).rule).toBe("block-aws");
    expect(r2.status).toBe(200);
    expect(debugOf(r2).applied).toBe("ALLOW");
    expect(debugOf(r2).rule).toBeUndefined();
  });

  it("velocity de um tenant não conta para o outro", async () => {
    const vel = { shards: 1, windowSec: 60, ip: 6, asn: 10000, fp: 10000, burstWindowSec: 5, ipBurst: 6 };
    const a = await createTenant({ ruleset: { mode: "enforce", velocity: vel } });
    const b = await createTenant({ ruleset: { mode: "enforce", velocity: vel } });
    const ctx = await evalHeader(CONN.humanBR, { ip: "177.10.20.40" });
    let onA: Response | undefined;
    for (let i = 0; i < 8; i++) onA = await visit(a.hostname, "/landing", chromeHeaders({ "x-eval-context": ctx }));
    expect(debugOf(onA!).signals).toContain("velocity:1*30");
    const onB = await visit(b.hostname, "/landing", chromeHeaders({ "x-eval-context": ctx }));
    expect(debugOf(onB).signals).not.toContain("velocity");
    expect(debugOf(onB).applied).toBe("ALLOW");
  });
});

async function fetchRaw(url: string): Promise<Response> {
  const { SELF } = await import("cloudflare:test");
  return SELF.fetch(url);
}
