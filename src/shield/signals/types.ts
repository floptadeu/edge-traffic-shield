import type { ConnInfo } from "../conn";
import type { Ruleset, SignalId } from "../ruleset";

// Contadores de velocity devolvidos pelo Durable Object.
export interface VelocityCounts {
  ip: number; // requests deste IP na janela principal
  ipBurst: number; // requests deste IP na janela curta
  asn: number; // requests deste ASN na janela (por shard)
  fp: number; // requests deste fingerprint na janela (por shard)
}

// Estado da atestação assíncrona (cookies assinados).
export type AttestationState =
  | { kind: "none" }
  | { kind: "attested" } // cookie de atestação válido
  | { kind: "challenged"; ageSec: number }; // recebeu SILENT_VERIFY há ageSec e ainda não atestou

export interface SignalInput {
  conn: ConnInfo;
  headers: Headers;
  url: URL;
  method: string;
  ruleset: Ruleset;
  fingerprint: string;
  attestation: AttestationState;
  // UA alegou ser um crawler da lista R1 mas a verificação por rDNS foi negativa.
  crawlerSpoof: boolean;
  velocity?: VelocityCounts; // ausente = DO indisponível (fail-open)
  trapHit?: boolean; // IP caiu num link-armadilha recentemente
}

// value em [-1, 1]: 1 = certeza de automação, -1 = evidência de humano.
export interface SignalResult {
  value: number;
  reason: string;
}

export interface Signal {
  id: SignalId;
  passive: boolean; // não depende de interação/JS do cliente
  description: string;
  // null = sinal não se aplica/não tem informação (não entra na soma).
  evaluate(input: SignalInput): SignalResult | null;
}

export function clamp01(n: number): number {
  return n < 0 ? 0 : n > 1 ? 1 : n;
}
