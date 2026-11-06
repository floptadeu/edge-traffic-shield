// R3 (obrigatório): falha de KV, D1, DO ou Queue resulta em ALLOW.
// Injeção de falha pelo header X-Shield-Chaos (só com DEV_FEATURES=true).
import { describe, expect, it } from "vitest";
import { brokenBinding, DegradedLog, safe } from "../src/lib/failopen";
import { CONN, createTenant, debugOf, evalHeader, visit } from "./e2e";
import { chromeHeaders } from "./helpers";

describe("R3 — fail-open", () => {
  it("KV fora: resolve tenant pelo D1 e segue (ALLOW, degraded=kv)", async () => {
    const t = await createTenant({ ruleset: { mode: "enforce" } });
    const res = await visit(t.hostname, "/landing", chromeHeaders({ "x-shield-chaos": "kv", "x-eval-context": await evalHeader(CONN.humanBR) }));
    expect(res.status).toBe(200);
    expect(debugOf(res).applied).toBe("ALLOW");
    expect(debugOf(res).degraded).toContain("kv=");
  });

  it("D1 fora: hot path nem percebe (nada de D1 síncrono por request)", async () => {
    const t = await createTenant({ ruleset: { mode: "enforce" } });
    const res = await visit(t.hostname, "/landing", chromeHeaders({ "x-shield-chaos": "d1", "x-eval-context": await evalHeader(CONN.humanBR) }));
    expect(res.status).toBe(200);
    expect(debugOf(res).degraded).toBeUndefined();
  });

  it("DO com erro: decide no Worker sem velocity (src=fallback) e um bot óbvio ainda é tratado", async () => {
    const t = await createTenant({ ruleset: { mode: "enforce" } });
    const human = await visit(t.hostname, "/landing", chromeHeaders({ "x-shield-chaos": "do", "x-eval-context": await evalHeader(CONN.humanBR) }));
    expect(human.status).toBe(200);
    expect(debugOf(human).src).toBe("fallback");
    expect(debugOf(human).applied).toBe("ALLOW");
    expect(debugOf(human).degraded).toContain("do=");
    const bot = await visit(t.hostname, "/landing", { "user-agent": "curl/8.4.0", "x-shield-chaos": "do", "x-eval-context": await evalHeader(CONN.awsTool) });
    expect(bot.status).toBe(200); // DECOY continua 200
    expect(debugOf(bot).src).toBe("fallback");
    expect(debugOf(bot).signals).not.toContain("velocity");
  });

  it("DO sem responder: timeout vira fallback, nunca pendura o visitante", async () => {
    const t = await createTenant({ ruleset: { mode: "enforce" } });
    const started = Date.now();
    const res = await visit(t.hostname, "/landing", chromeHeaders({ "x-shield-chaos": "do-hang", "x-eval-context": await evalHeader(CONN.humanBR) }));
    expect(res.status).toBe(200);
    expect(debugOf(res).src).toBe("fallback");
    expect(debugOf(res).degraded).toContain("do=timeout");
    expect(Date.now() - started).toBeLessThan(5000);
  }, 10_000);

  it("Queue fora: eventos se perdem em silêncio, o visitante não", async () => {
    const t = await createTenant({ ruleset: { mode: "enforce" } });
    for (let i = 0; i < 3; i++) {
      const res = await visit(t.hostname, "/landing", chromeHeaders({ "x-shield-chaos": "queue", "x-eval-context": await evalHeader(CONN.humanBR) }));
      expect(res.status).toBe(200);
    }
  });

  it("tudo fora (KV + DO + Queue) com tenant já em memória: ALLOW", async () => {
    const t = await createTenant({ ruleset: { mode: "enforce" } });
    await visit(t.hostname, "/landing", chromeHeaders()); // aquece o memo do hostname
    const res = await visit(t.hostname, "/landing", chromeHeaders({ "x-shield-chaos": "kv,do,queue,d1", "x-eval-context": await evalHeader(CONN.humanBR) }));
    expect(res.status).toBe(200);
    expect(debugOf(res).applied).toBe("ALLOW");
  });

  it("safe(): erro e timeout devolvem o fallback e registram o motivo", async () => {
    const log = new DegradedLog();
    expect(await safe("x", Promise.reject(new Error("boom")), 42, log)).toBe(42);
    expect(await safe("y", new Promise<number>(() => {}), 7, log, 20)).toBe(7);
    expect(log.toString()).toBe("x=boom,y=timeout");
    const kv = brokenBinding<KVNamespace>("kv");
    await expect(kv.get("a")).rejects.toThrow("chaos:kv.get");
  });
});
