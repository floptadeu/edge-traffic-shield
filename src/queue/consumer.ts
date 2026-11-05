// Consumer da Queue: cada mensagem é um lote de eventos de um shard.
// Idempotente por batchId (tabela event_batches) e uma única D1.batch()
// transacional por invocação: ou aplica tudo ou nada (e a Queue reentrega).

import type { Env } from "../env";
import type { EventBatchMessage } from "../do/protocol";

const STATS_COLS = 5; // tenant_id, minute, verdict, n, score_sum
const EVENT_COLS = 12;
const MAX_PARAMS = 100; // limite do D1 por statement

function chunk<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

export async function consumeEvents(batch: MessageBatch<EventBatchMessage>, env: Env): Promise<void> {
  const messages = batch.messages;
  if (!messages.length) return;

  // Lotes já aplicados (reentrega) e duplicados dentro da mesma leva.
  const ids = [...new Set(messages.map((m) => m.body.batchId))];
  const placeholders = ids.map(() => "?").join(",");
  const existing = new Set(
    (await env.DB.prepare(`SELECT batch_id FROM event_batches WHERE batch_id IN (${placeholders})`).bind(...ids).all<{ batch_id: string }>())
      .results.map((r) => r.batch_id),
  );

  const stmts: D1PreparedStatement[] = [];
  const toAck: Message<EventBatchMessage>[] = [];
  const seen = new Set<string>();
  const now = Date.now();

  for (const m of messages) {
    const b = m.body;
    if (existing.has(b.batchId) || seen.has(b.batchId)) {
      toAck.push(m); // já aplicado: só confirma
      continue;
    }
    seen.add(b.batchId);
    toAck.push(m);
    stmts.push(env.DB.prepare("INSERT INTO event_batches (batch_id, tenant_id, received_at) VALUES (?, ?, ?)").bind(b.batchId, b.tenantId, now));

    for (const rows of chunk(b.agg, Math.floor(MAX_PARAMS / STATS_COLS))) {
      const values = rows.map(() => "(?, ?, ?, ?, ?)").join(",");
      const params = rows.flatMap((r) => [b.tenantId, r.minute, r.verdict, r.n, r.scoreSum]);
      stmts.push(
        env.DB.prepare(
          `INSERT INTO stats_minute (tenant_id, minute, verdict, n, score_sum) VALUES ${values}
           ON CONFLICT(tenant_id, minute, verdict) DO UPDATE SET n = n + excluded.n, score_sum = score_sum + excluded.score_sum`,
        ).bind(...params),
      );
    }

    for (const rows of chunk(b.samples, Math.floor(MAX_PARAMS / EVENT_COLS))) {
      const values = rows.map(() => "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").join(",");
      const params = rows.flatMap((e) => [b.tenantId, e.ts, e.host, e.path, e.ipHash, e.asn, e.country, e.colo, e.verdict, e.applied, e.score, e.signals]);
      stmts.push(
        env.DB.prepare(
          `INSERT INTO events (tenant_id, ts, host, path, ip_hash, asn, country, colo, verdict, applied, score, signals) VALUES ${values}`,
        ).bind(...params),
      );
    }
  }

  try {
    if (stmts.length) await env.DB.batch(stmts);
    for (const m of toAck) m.ack();
  } catch {
    // D1 indisponível: reentrega tudo (idempotência garante que não duplica).
    for (const m of messages) m.retry();
  }
}
