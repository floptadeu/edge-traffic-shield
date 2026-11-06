// Score 0–100 e veredito. Função pura: usada pelo Durable Object (caminho
// normal, com velocity) e pelo Worker (fallback sem velocity).

import type { Mode, Rule, RuleCondition, Ruleset, SignalId, Verdict } from "./ruleset";
import { SIGNALS, type Signal, type SignalInput, type VelocityCounts } from "./signals";
import { trapSignal } from "./signals/trap";
import { velocitySignal } from "./signals/velocity";

export interface Contribution {
  id: SignalId;
  value: number; // [-1, 1]
  weight: number;
  points: number; // value * weight
  reason: string;
}

export interface Decision {
  score: number;
  verdict: Verdict; // veredito calculado
  contributions: Contribution[];
  rule?: string; // id da regra explícita que decidiu, se houver
}

export function evaluateSignals(input: SignalInput, signals: readonly Signal[] = SIGNALS): Contribution[] {
  const out: Contribution[] = [];
  for (const s of signals) {
    let r: ReturnType<Signal["evaluate"]> = null;
    try {
      r = s.evaluate(input);
    } catch {
      // Um sinal com bug nunca derruba a decisão: só não contribui.
      r = null;
    }
    if (!r) continue;
    const weight = input.ruleset.weights[s.id] ?? 0;
    out.push({ id: s.id, value: r.value, weight, points: r.value * weight, reason: r.reason });
  }
  return out;
}

export function scoreFrom(contributions: Contribution[]): number {
  const sum = contributions.reduce((acc, c) => acc + c.points, 0);
  return Math.max(0, Math.min(100, Math.round(sum)));
}

export function verdictFromScore(score: number, ruleset: Ruleset): Verdict {
  const t = ruleset.thresholds;
  if (score >= t.block) return "BLOCK";
  if (score >= t.decoy) return "DECOY";
  if (score >= t.silent_verify) return "SILENT_VERIFY";
  return "ALLOW";
}

export interface RuleContext {
  ip: string;
  asn: number;
  country: string;
  path: string;
  host: string;
  ua: string;
  score: number;
}

function fieldValue(ctx: RuleContext, c: RuleCondition): string | number {
  return ctx[c.field];
}

export function matchCondition(ctx: RuleContext, c: RuleCondition): boolean {
  const actual = fieldValue(ctx, c);
  const want = c.value;
  switch (c.op) {
    case "eq":
      return String(actual).toLowerCase() === String(want).toLowerCase();
    case "in":
      return Array.isArray(want) && want.some((w) => String(w).toLowerCase() === String(actual).toLowerCase());
    case "prefix":
      return typeof want === "string" && String(actual).toLowerCase().startsWith(want.toLowerCase());
    case "contains":
      return typeof want === "string" && String(actual).toLowerCase().includes(want.toLowerCase());
    case "gte":
      return typeof want === "number" && Number(actual) >= want;
    case "lte":
      return typeof want === "number" && Number(actual) <= want;
  }
}

export function applyRules(rules: Rule[], ctx: RuleContext): Rule | undefined {
  for (const r of rules) {
    try {
      if (matchCondition(ctx, r.if)) return r;
    } catch {
      // regra malformada em runtime: ignora
    }
  }
  return undefined;
}

export interface ClosedDecision {
  verdict: Verdict;
  applied: Verdict;
  mode: Mode;
  score: number;
  contributions: Contribution[];
  rule?: string;
}

// Fecha a decisão a partir dos sinais já avaliados no Worker + velocity/trap
// (quando conhecidos). Única implementação da fórmula: o Durable Object e o
// fallback do Worker chamam esta função.
export function closeDecision(
  signals: ReadonlyArray<{ id: SignalId; value: number; reason: string }>,
  ruleset: Ruleset,
  ruleCtx: Omit<RuleContext, "score">,
  local: { velocity?: VelocityCounts; trapHit?: boolean; reasonSuffix?: string } = {},
): ClosedDecision {
  const contributions: Contribution[] = signals.map((s) => {
    const weight = ruleset.weights[s.id] ?? 0;
    return { id: s.id, value: s.value, weight, points: s.value * weight, reason: s.reason };
  });
  const localInput = { ruleset, velocity: local.velocity, trapHit: local.trapHit } as SignalInput;
  for (const sig of [velocitySignal, trapSignal]) {
    const r = sig.evaluate(localInput);
    if (!r) continue;
    const weight = ruleset.weights[sig.id] ?? 0;
    const reason = local.reasonSuffix ? `${r.reason}${local.reasonSuffix}` : r.reason;
    contributions.push({ id: sig.id, value: r.value, weight, points: r.value * weight, reason });
  }
  const score = scoreFrom(contributions);
  let verdict = verdictFromScore(score, ruleset);
  let rule: string | undefined;
  const matched = applyRules(ruleset.rules, { ...ruleCtx, score });
  if (matched) {
    verdict = matched.verdict;
    rule = matched.id;
  }
  const applied: Verdict = ruleset.mode === "monitor" ? "ALLOW" : verdict;
  return { verdict, applied, mode: ruleset.mode, score, contributions, ...(rule ? { rule } : {}) };
}

export function decide(input: SignalInput, host: string): Decision {
  const contributions = evaluateSignals(input);
  const score = scoreFrom(contributions);
  let verdict = verdictFromScore(score, input.ruleset);
  const rule = applyRules(input.ruleset.rules, {
    ip: input.conn.ip,
    asn: input.conn.asn,
    country: input.conn.country,
    path: input.url.pathname,
    host,
    ua: input.headers.get("user-agent") ?? "",
    score,
  });
  if (rule) verdict = rule.verdict;
  return { score, verdict, contributions, ...(rule ? { rule: rule.id } : {}) };
}

// Formato compacto para header de debug e eventos: "asn:1*20,ua:1*20".
export function formatContributions(cs: Contribution[]): string {
  return cs
    .filter((c) => c.points !== 0)
    .map((c) => `${c.id}:${trim(c.value)}*${c.weight}(${c.reason})`)
    .join(",");
}

function trim(n: number): string {
  return Number.isInteger(n) ? String(n) : n.toFixed(2).replace(/0+$/, "").replace(/\.$/, "");
}
