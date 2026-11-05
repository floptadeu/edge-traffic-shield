// Sinal "trap" (ativo): páginas DECOY carregam um link invisível para
// /__ets/t/<token>. Humano não vê, crawler segue. Quem segue é marcado no
// Durable Object por alguns minutos e passa a receber este sinal.

import type { Signal, SignalInput, SignalResult } from "./types";

export const trapSignal: Signal = {
  id: "trap",
  passive: false,
  description: "IP seguiu um link-armadilha invisível recentemente",
  evaluate(input: SignalInput): SignalResult | null {
    return input.trapHit ? { value: 1, reason: "followed-trap" } : null;
  },
};
