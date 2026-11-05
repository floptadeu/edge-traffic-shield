// Sinal "attestation" (ativo, assíncrono — R2): em SILENT_VERIFY a página
// recebe um script invisível que executa Turnstile (modo invisible) ou, sem
// Turnstile configurado, só prova que JS rodou. O beacon grava um cookie
// assinado; a atestação vale para as requisições SEGUINTES.
//   attested          => -1 (evidência forte de humano, reduz o score)
//   desafiado e ignorou => +0.7 (não executou JS / falhou no Turnstile).
//   Não é +1 de propósito: humano com JS bloqueado existe e custa 10x.

import type { Signal, SignalInput, SignalResult } from "./types";

export const attestationSignal: Signal = {
  id: "attestation",
  passive: false,
  description: "Atestação invisível assíncrona (Turnstile invisible / JS) via cookie assinado",
  evaluate(input: SignalInput): SignalResult | null {
    const a = input.attestation;
    if (a.kind === "attested") return { value: -1, reason: "attested" };
    if (a.kind === "challenged" && a.ageSec > input.ruleset.attestation.challengeGraceSec)
      return { value: 0.7, reason: `challenge-ignored:${a.ageSec}s` };
    return null;
  },
};
