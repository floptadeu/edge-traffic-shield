// Contrato entre Worker e Durable Objects (RPC). Mantido pequeno de propósito:
// o Worker manda o que já calculou e as chaves de velocity; o DO devolve a decisão.

import type { Mode, SignalId, Verdict } from "../shield/ruleset";
import type { Contribution } from "../shield/score";
import type { RuleContext } from "../shield/score";

// Valor cru de um sinal já avaliado no Worker (sem peso).
export interface SignalValue {
  id: SignalId;
  value: number;
  reason: string;
}

export interface ShardRequest {
  tenantId: string;
  ts: number; // epoch ms
  keys: { ip: string; asn: number; fp: string };
  // Sinais calculados no Worker (passivos + atestação). O DO acrescenta velocity e trap.
  signals: SignalValue[];
  rule: RuleContext; // campos para as regras explícitas
  // Versão de ruleset que o Worker usou para calcular os sinais (só informativo).
  workerRulesetVersion: number;
  // Veredito forçado (crawler verificado = R1). O DO só registra o evento.
  forced?: { verdict: Verdict; reason: string };
  event: { host: string; path: string; country: string; colo: string };
}

export interface ShardResponse {
  verdict: Verdict; // calculado
  applied: Verdict; // o que aplicar (ALLOW em monitor)
  mode: Mode;
  score: number;
  contributions: Contribution[];
  rule?: string;
  rulesetVersion: number;
  velocity: { ip: number; ipBurst: number; asn: number; fp: number };
}

// Amostra individual de evento (vai no lote para a Queue e depois para o D1).
export interface EventSample {
  ts: number;
  host: string;
  path: string;
  ipHash: string;
  asn: number;
  country: string;
  colo: string;
  verdict: Verdict;
  applied: Verdict;
  score: number;
  signals: string; // formato compacto
}

export interface AggRow {
  minute: number;
  verdict: Verdict;
  n: number;
  scoreSum: number;
}

// Uma mensagem na Queue = um lote de até N eventos de um shard.
export interface EventBatchMessage {
  batchId: string; // `${shardName}:${seq}` — chave de idempotência
  tenantId: string;
  shard: string;
  from: number;
  to: number;
  total: number; // eventos representados (agregado exato)
  agg: AggRow[];
  samples: EventSample[]; // 100% dos não-ALLOW + 1:10 dos ALLOW, com teto
}
