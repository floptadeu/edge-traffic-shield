// Durable Objects e consumer: janela deslizante, lotes/amostragem e idempotência.
import { createExecutionContext, createMessageBatch, env, getQueueResult, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../src/index";
import type { EventBatchMessage, ShardRequest } from "../src/do/protocol";
import type { ShieldShard } from "../src/do/ShieldShard";
import { consumeEvents } from "../src/queue/consumer";

function shardReq(over: Partial<ShardRequest> = {}, ip = "10.0.0.1", ts = Date.now()): ShardRequest {
  return {
    tenantId: "do-test",
    ts,
    keys: { ip, asn: 100, fp: "fpx" },
    signals: [],
    rule: { ip, asn: 100, country: "BR", path: "/", host: "h", ua: "", score: 0 },
    workerRulesetVersion: 0,
    event: { host: "h", path: "/", country: "BR", colo: "GRU" },
    ...over,
  };
}

function stub(name = `do-test:GRU:${Math.random()}`): DurableObjectStub<ShieldShard> {
  return env.SHIELD_SHARD.get(env.SHIELD_SHARD.idFromName(name));
}

describe("ShieldShard", () => {
  it("conta por IP em janela deslizante e esquece o que saiu da janela", async () => {
    const s = stub();
    const t0 = 1_800_000_000_000;
    for (let i = 0; i < 5; i++) await s.evaluate(shardReq({}, "1.1.1.1", t0 + i * 100));
    let r = await s.evaluate(shardReq({}, "1.1.1.1", t0 + 600));
    expect(r.velocity.ip).toBe(6);
    expect(r.velocity.ipBurst).toBe(6);
    // 61 s depois: janela de 60 s zerou (o próprio request conta 1)
    r = await s.evaluate(shardReq({}, "1.1.1.1", t0 + 61_000));
    expect(r.velocity.ip).toBe(1);
    // IP diferente, mesmo ASN/fp: contadores separados por chave
    r = await s.evaluate(shardReq({}, "2.2.2.2", t0 + 61_100));
    expect(r.velocity.ip).toBe(1);
    expect(r.velocity.asn).toBe(2);
    expect(r.velocity.fp).toBe(2);
  });

  it("sem ruleset publicado usa o default (monitor) e aplica ALLOW", async () => {
    const r = await stub().evaluate(shardReq({ signals: [{ id: "ua", value: 1, reason: "tool" }, { id: "asn", value: 1, reason: "dc" }] }));
    expect(r.mode).toBe("monitor");
    expect(r.verdict).toBe("SILENT_VERIFY"); // 30 + 25 = 55
    expect(r.applied).toBe("ALLOW");
    expect(r.rulesetVersion).toBe(0);
  });

  it("veredito forçado (R1) não pontua e é registrado", async () => {
    const r = await stub().evaluate(shardReq({ forced: { verdict: "ALLOW", reason: "verified-crawler:google" }, signals: [{ id: "ua", value: 1, reason: "x" }] }));
    expect(r.score).toBe(0);
    expect(r.applied).toBe("ALLOW");
    expect(r.rule).toBe("verified-crawler:google");
  });

  it("lote: 100 eventos viram UMA mensagem com agregado exato e amostras limitadas", async () => {
    const s = stub("do-test:GRU:batch");
    const sent: EventBatchMessage[] = [];
    const orig = env.EVENTS_QUEUE.send.bind(env.EVENTS_QUEUE);
    env.EVENTS_QUEUE.send = (async (m: EventBatchMessage) => { sent.push(m); }) as never;
    try {
      const t0 = 1_800_000_000_000;
      for (let i = 0; i < 100; i++) {
        // 80 ALLOW (sinais vazios) + 20 com score alto
        const signals = i % 5 === 0 ? [{ id: "ua" as const, value: 1, reason: "tool" }, { id: "asn" as const, value: 1, reason: "dc" }, { id: "headers" as const, value: 1, reason: "x" }] : [];
        await s.evaluate(shardReq({ signals }, `9.9.9.${i}`, t0 + i * 10));
      }
      await new Promise((r) => setTimeout(r, 50));
      expect(sent.length).toBe(1);
      const m = sent[0]!;
      expect(m.total).toBe(100);
      expect(m.agg.reduce((a, r) => a + r.n, 0)).toBe(100);
      const allowSamples = m.samples.filter((e) => e.verdict === "ALLOW").length;
      const otherSamples = m.samples.filter((e) => e.verdict !== "ALLOW").length;
      expect(otherSamples).toBe(20); // 100% dos não-ALLOW
      expect(allowSamples).toBe(8); // 1:10 dos 80 ALLOW
      expect(JSON.stringify(m).length).toBeLessThan(64 * 1024); // 1 operação de Queue
      expect(m.batchId).toContain(":1:");
    } finally {
      env.EVENTS_QUEUE.send = orig as never;
    }
  });

  it("markTrap marca o IP por um tempo", async () => {
    const s = stub();
    await s.markTrap("5.5.5.5", 1_800_000_000_000);
    const hit = await s.evaluate(shardReq({}, "5.5.5.5", 1_800_000_001_000));
    expect(hit.contributions.some((c) => c.id === "trap")).toBe(true);
    const later = await s.evaluate(shardReq({}, "5.5.5.5", 1_800_000_000_000 + 11 * 60_000));
    expect(later.contributions.some((c) => c.id === "trap")).toBe(false);
  });
});

describe("consumer idempotente", () => {
  const msg = (batchId: string, n = 3): EventBatchMessage => ({
    batchId,
    tenantId: "cons",
    shard: "s",
    from: 1,
    to: 2,
    total: n,
    agg: [{ minute: 28_333_333, verdict: "ALLOW", n, scoreSum: 0 }],
    samples: Array.from({ length: n }, (_, i) => ({ ts: 1_700_000_000_000 + i, host: "h", path: "/", ipHash: "x", asn: 1, country: "BR", colo: "GRU", verdict: "ALLOW" as const, applied: "ALLOW" as const, score: 0, signals: "" })),
  });

  async function counts() {
    const ev = await env.DB.prepare("SELECT COUNT(*) AS c FROM events WHERE tenant_id = 'cons'").first<{ c: number }>();
    const st = await env.DB.prepare("SELECT SUM(n) AS n FROM stats_minute WHERE tenant_id = 'cons'").first<{ n: number }>();
    return { events: ev!.c, n: st!.n ?? 0 };
  }

  it("mesma mensagem entregue duas vezes (e duplicada no mesmo lote) aplica uma vez", async () => {
    const b1 = createMessageBatch<EventBatchMessage>("ets-events", [
      { id: "1", timestamp: new Date(), body: msg("b-1"), attempts: 1 },
      { id: "2", timestamp: new Date(), body: msg("b-1"), attempts: 1 }, // duplicada no mesmo lote
      { id: "3", timestamp: new Date(), body: msg("b-2", 2), attempts: 1 },
    ]);
    const ctx = createExecutionContext();
    await worker.queue!(b1 as never, env as never, ctx);
    const r1 = await getQueueResult(b1, ctx);
    expect(r1.explicitAcks).toHaveLength(3);
    expect(await counts()).toEqual({ events: 5, n: 5 });

    // reentrega
    const b2 = createMessageBatch<EventBatchMessage>("ets-events", [{ id: "4", timestamp: new Date(), body: msg("b-1"), attempts: 2 }]);
    const ctx2 = createExecutionContext();
    await worker.queue!(b2 as never, env as never, ctx2);
    expect((await getQueueResult(b2, ctx2)).explicitAcks).toHaveLength(1);
    expect(await counts()).toEqual({ events: 5, n: 5 });
  });

  it("D1 indisponível: retry de tudo, nada confirmado", async () => {
    const acked: string[] = [];
    const retried: string[] = [];
    const batch = {
      queue: "ets-events",
      messages: [{ id: "x", body: msg("b-x"), timestamp: new Date(), attempts: 1, ack: () => acked.push("x"), retry: () => retried.push("x") }],
      ackAll() {},
      retryAll() {},
    } as unknown as MessageBatch<EventBatchMessage>;
    const broken = { ...env, DB: { prepare: () => { throw new Error("d1 down"); } } } as never;
    await expect(consumeEvents(batch, broken)).rejects.toThrow(); // o SELECT inicial falha: a Queue reentrega
    expect(acked).toEqual([]);
  });
});

// Mantém o helper importado "em uso" para o lint do TS.
void runInDurableObject;
