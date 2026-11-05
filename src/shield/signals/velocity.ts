// Sinal "velocity": janela deslizante por IP, ASN e fingerprint (contadores
// vêm do Durable Object). Sobe de forma gradual: 0 até metade do limite,
// 1 no limite. Sem contadores (DO indisponível) o sinal não se aplica.

import { clamp01, type Signal, type SignalInput, type SignalResult } from "./types";

function ramp(count: number, limit: number): number {
  if (limit <= 0) return 0;
  const ratio = count / limit;
  return clamp01((ratio - 0.5) * 2);
}

export const velocitySignal: Signal = {
  id: "velocity",
  passive: true,
  description: "Rate por IP (janela + rajada), ASN e fingerprint em janela deslizante",
  evaluate(input: SignalInput): SignalResult | null {
    const v = input.velocity;
    if (!v) return null;
    const cfg = input.ruleset.velocity;
    const parts: Array<[number, string]> = [
      [ramp(v.ip, cfg.ip), `ip=${v.ip}/${cfg.ip}`],
      [ramp(v.ipBurst, cfg.ipBurst), `burst=${v.ipBurst}/${cfg.ipBurst}`],
      [ramp(v.asn, cfg.asn), `asn=${v.asn}/${cfg.asn}`],
      [ramp(v.fp, cfg.fp), `fp=${v.fp}/${cfg.fp}`],
    ];
    parts.sort((a, b) => b[0] - a[0]);
    const top = parts[0]!;
    return { value: top[0], reason: top[0] > 0 ? parts.filter((p) => p[0] > 0).map((p) => p[1]).join("+") : top[1] };
  },
};
