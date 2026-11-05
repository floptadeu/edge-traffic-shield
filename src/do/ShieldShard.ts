// Durable Object por (tenant, colo, shard). Responsável por:
//   1. velocity em janela deslizante (IP, ASN, fingerprint) em memória;
//   2. fechar a decisão com o ruleset ATIVO (versão vinda do TenantConfig);
//   3. acumular eventos e mandar para a Queue em lotes (cota de 10k ops/dia).
// Tudo em memória de propósito: zero linhas SQLite por request. Se o DO for
// despejado, os contadores zeram e recomeçam — aceitável para rate limiting.

import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";
import { fnv1a } from "../lib/crypto";
import { DEFAULT_RULESET, parseStoredRuleset, type Ruleset, type Verdict } from "../shield/ruleset";
import { applyRules, formatContributions, scoreFrom, verdictFromScore, type Contribution } from "../shield/score";
import { velocitySignal } from "../shield/signals/velocity";
import { trapSignal } from "../shield/signals/trap";
import type { SignalInput, VelocityCounts } from "../shield/signals";
import type { AggRow, EventBatchMessage, EventSample, ShardRequest, ShardResponse } from "./protocol";

const POLL_INTERVAL_MS = 2000; // intervalo de consulta da versão ao TenantConfig
const FLUSH_EVERY_EVENTS = 100; // lote cheio
const FLUSH_EVERY_MS = 30_000; // ou a cada 30 s com tráfego baixo
const MAX_SAMPLES_PER_BATCH = 60; // mantém a mensagem < 64 KB (1 operação de Queue)
const ALLOW_SAMPLE_RATE = 10; // 1 em 10 ALLOW vira amostra individual
const TRAP_TTL_MS = 10 * 60_000;
const MAX_WINDOW_SEC = 300;

// Contador deslizante com baldes de 1 segundo. count(span) soma os últimos `span` s.
class SlidingCounter {
  private readonly buckets: Uint32Array;
  private readonly stamps: Int32Array; // segundo a que cada balde pertence
  lastSec = 0;
  constructor(private readonly size: number) {
    this.buckets = new Uint32Array(size);
    this.stamps = new Int32Array(size);
  }
  hit(nowSec: number): void {
    const i = nowSec % this.size;
    if (this.stamps[i] !== nowSec) {
      this.stamps[i] = nowSec;
      this.buckets[i] = 0;
    }
    this.buckets[i]!++;
    this.lastSec = nowSec;
  }
  count(nowSec: number, spanSec: number): number {
    let total = 0;
    const min = nowSec - spanSec; // exclusivo
    for (let i = 0; i < this.size; i++) {
      if (this.stamps[i]! > min && this.stamps[i]! <= nowSec) total += this.buckets[i]!;
    }
    return total;
  }
}

export class ShieldShard extends DurableObject<Env> {
  private tenantId = "";
  private shardName = "";
  private ruleset: Ruleset = DEFAULT_RULESET;
  private rulesetVersion = 0;
  private lastPoll = 0;
  private polling: Promise<void> | null = null;

  private counters = new Map<string, SlidingCounter>();
  private lastPrune = 0;
  private traps = new Map<string, number>(); // ip -> expiresAt

  private seq = 0;
  private pendingTotal = 0;
  private pendingFrom = 0;
  private agg = new Map<string, AggRow>();
  private samples: EventSample[] = [];
  private allowSeen = 0;
  private flushing: Promise<void> | null = null;

  // ----- decisão -----------------------------------------------------------

  async evaluate(req: ShardRequest): Promise<ShardResponse> {
    this.bind(req.tenantId);
    this.maybeRefreshRuleset(req.ts);
    const rs = this.ruleset;
    const nowSec = Math.floor(req.ts / 1000);

    const velocity = this.hitAndCount(req.keys, nowSec, rs);
    const trapHit = this.isTrapped(req.keys.ip, req.ts);

    let contributions: Contribution[];
    let score: number;
    let verdict: Verdict;
    let rule: string | undefined;

    if (req.forced) {
      contributions = [];
      score = 0;
      verdict = req.forced.verdict;
      rule = req.forced.reason;
    } else {
      contributions = req.signals.map((s) => {
        const weight = rs.weights[s.id] ?? 0;
        return { id: s.id, value: s.value, weight, points: s.value * weight, reason: s.reason };
      });
      // Sinais que só o DO conhece.
      const local: Pick<SignalInput, "ruleset" | "velocity" | "trapHit"> = { ruleset: rs, velocity, trapHit };
      for (const sig of [velocitySignal, trapSignal]) {
        const r = sig.evaluate(local as SignalInput);
        if (r) {
          const weight = rs.weights[sig.id] ?? 0;
          contributions.push({ id: sig.id, value: r.value, weight, points: r.value * weight, reason: r.reason });
        }
      }
      score = scoreFrom(contributions);
      verdict = verdictFromScore(score, rs);
      const matched = applyRules(rs.rules, { ...req.rule, score });
      if (matched) {
        verdict = matched.verdict;
        rule = matched.id;
      }
    }

    const applied: Verdict = rs.mode === "monitor" ? "ALLOW" : verdict;
    this.record(req, verdict, applied, score, contributions);

    return {
      verdict,
      applied,
      mode: rs.mode,
      score,
      contributions,
      ...(rule ? { rule } : {}),
      rulesetVersion: this.rulesetVersion,
      velocity,
    };
  }

  async markTrap(ip: string, ts: number = Date.now()): Promise<void> {
    this.traps.set(ip, ts + TRAP_TTL_MS);
  }

  // Força o flush (usado em testes e no alarme).
  async flush(): Promise<void> {
    await this.doFlush();
  }

  // Estado para testes/observabilidade.
  async debugState(): Promise<{ rulesetVersion: number; pendingTotal: number; samples: number; counters: number }> {
    return {
      rulesetVersion: this.rulesetVersion,
      pendingTotal: this.pendingTotal,
      samples: this.samples.length,
      counters: this.counters.size,
    };
  }

  override async alarm(): Promise<void> {
    await this.doFlush();
  }

  // ----- velocity ----------------------------------------------------------

  private hitAndCount(keys: ShardRequest["keys"], nowSec: number, rs: Ruleset): VelocityCounts {
    const win = Math.min(rs.velocity.windowSec, MAX_WINDOW_SEC);
    const ipC = this.counter(`ip:${keys.ip}`, win);
    const asnC = this.counter(`asn:${keys.asn}`, win);
    const fpC = this.counter(`fp:${keys.fp}`, win);
    ipC.hit(nowSec);
    asnC.hit(nowSec);
    fpC.hit(nowSec);
    if (nowSec - this.lastPrune > win) this.prune(nowSec, win);
    return {
      ip: ipC.count(nowSec, win),
      ipBurst: ipC.count(nowSec, rs.velocity.burstWindowSec),
      asn: asnC.count(nowSec, win),
      fp: fpC.count(nowSec, win),
    };
  }

  private counter(key: string, size: number): SlidingCounter {
    let c = this.counters.get(key);
    if (!c) {
      c = new SlidingCounter(size);
      this.counters.set(key, c);
    }
    return c;
  }

  private prune(nowSec: number, win: number): void {
    this.lastPrune = nowSec;
    for (const [k, c] of this.counters) if (nowSec - c.lastSec > win) this.counters.delete(k);
    const nowMs = nowSec * 1000;
    for (const [ip, exp] of this.traps) if (exp < nowMs) this.traps.delete(ip);
  }

  private isTrapped(ip: string, ts: number): boolean {
    const exp = this.traps.get(ip);
    return exp !== undefined && exp > ts;
  }

  // ----- ruleset -----------------------------------------------------------

  private bind(tenantId: string): void {
    if (!this.tenantId) {
      this.tenantId = tenantId;
      this.shardName = this.ctx.id.toString().slice(0, 12);
    }
  }

  // Não bloqueia a requisição: a versão nova entra na próxima. Propagação
  // típica: <= 2 s (intervalo) + alguns ms (KV da chave imutável).
  private maybeRefreshRuleset(now: number): void {
    if (this.polling || now - this.lastPoll < POLL_INTERVAL_MS) return;
    this.lastPoll = now;
    this.polling = this.refreshRuleset().finally(() => {
      this.polling = null;
    });
    this.ctx.waitUntil(this.polling);
  }

  private async refreshRuleset(): Promise<void> {
    try {
      let version = 0;
      try {
        const cfg = this.env.TENANT_CONFIG.get(this.env.TENANT_CONFIG.idFromName(this.tenantId));
        version = await cfg.getVersion();
      } catch {
        // TenantConfig indisponível: cai no ponteiro do KV (eventualmente consistente).
      }
      if (!version) {
        const ptr = await this.env.CONFIG_KV.get(`rsptr:${this.tenantId}`, { type: "json", cacheTtl: 60 });
        version = typeof (ptr as { version?: unknown } | null)?.version === "number" ? (ptr as { version: number }).version : 0;
      }
      if (!version || version === this.rulesetVersion) return;
      const body = await this.env.CONFIG_KV.get(`ruleset:${this.tenantId}:${version}`, { cacheTtl: 86400 });
      if (!body) return; // ainda não visível: tenta no próximo ciclo
      this.ruleset = parseStoredRuleset(body);
      this.rulesetVersion = version;
    } catch {
      // mantém a versão atual (fail-open para a configuração)
    }
  }

  // ----- eventos -----------------------------------------------------------

  private record(req: ShardRequest, verdict: Verdict, applied: Verdict, score: number, cs: Contribution[]): void {
    const minute = Math.floor(req.ts / 60_000);
    const k = `${minute}:${verdict}`;
    const row = this.agg.get(k);
    if (row) {
      row.n++;
      row.scoreSum += score;
    } else this.agg.set(k, { minute, verdict, n: 1, scoreSum: score });

    if (this.pendingTotal === 0) {
      this.pendingFrom = req.ts;
      this.ctx.waitUntil(this.ctx.storage.setAlarm(req.ts + FLUSH_EVERY_MS).catch(() => {}));
    }
    this.pendingTotal++;

    const keep = verdict !== "ALLOW" || ++this.allowSeen % ALLOW_SAMPLE_RATE === 0;
    if (keep && this.samples.length < MAX_SAMPLES_PER_BATCH) {
      this.samples.push({
        ts: req.ts,
        host: req.event.host,
        path: req.event.path.slice(0, 200),
        ipHash: fnv1a(req.keys.ip).toString(36),
        asn: req.keys.asn,
        country: req.event.country,
        colo: req.event.colo,
        verdict,
        applied,
        score,
        signals: formatContributions(cs).slice(0, 400),
      });
    }

    if (this.pendingTotal >= FLUSH_EVERY_EVENTS) this.ctx.waitUntil(this.doFlush());
  }

  private async doFlush(): Promise<void> {
    if (this.flushing) return this.flushing;
    if (this.pendingTotal === 0) return;
    const msg: EventBatchMessage = {
      batchId: `${this.shardName}:${++this.seq}:${this.pendingFrom}`,
      tenantId: this.tenantId,
      shard: this.shardName,
      from: this.pendingFrom,
      to: Date.now(),
      total: this.pendingTotal,
      agg: [...this.agg.values()],
      samples: this.samples,
    };
    // Zera antes de enviar: se a Queue falhar, perdemos este lote e seguimos
    // (fail-open). Guardar e reenviar criaria crescimento sem limite.
    this.agg = new Map();
    this.samples = [];
    this.pendingTotal = 0;
    this.flushing = this.env.EVENTS_QUEUE.send(msg)
      .then(() => undefined, () => undefined)
      .finally(() => {
        this.flushing = null;
      });
    await this.flushing;
  }
}
