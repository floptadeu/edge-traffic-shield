// Ruleset declarativo por tenant: pesos, limiares, velocity, regras explícitas.
// Versionado e imutável (cada PUT gera uma versão nova; rollback só move o ponteiro).

export type Verdict = "ALLOW" | "SILENT_VERIFY" | "DECOY" | "BLOCK";
export type Mode = "monitor" | "enforce";

export const VERDICTS: readonly Verdict[] = ["ALLOW", "SILENT_VERIFY", "DECOY", "BLOCK"];

// Identificadores dos sinais. A ordem aqui é a ordem do header de debug.
export const SIGNAL_IDS = [
  "asn",
  "tls",
  "headers",
  "ua",
  "geo",
  "path",
  "velocity",
  "trap",
  "attestation",
] as const;
export type SignalId = (typeof SIGNAL_IDS)[number];

export type RuleField = "ip" | "asn" | "country" | "path" | "host" | "score" | "ua";
export type RuleOp = "eq" | "in" | "prefix" | "contains" | "gte" | "lte";

export interface RuleCondition {
  field: RuleField;
  op: RuleOp;
  value: string | number | Array<string | number>;
}

// Regra explícita: avaliada depois do score. Primeira que casar vence.
// Nunca se aplica a crawler verificado (R1 roda antes e não é sobrescrevível).
export interface Rule {
  id: string;
  if: RuleCondition;
  verdict: Verdict;
}

export interface Ruleset {
  mode: Mode;
  // Peso de cada sinal. score = clamp(0..100, soma(valor_i * peso_i)); valor_i em [-1, 1].
  weights: Record<SignalId, number>;
  // Limiares de veredito (score >= limiar). ALLOW abaixo de silent_verify.
  thresholds: { silent_verify: number; decoy: number; block: number };
  velocity: {
    shards: number; // DOs por (tenant, colo); IP sempre cai no mesmo shard
    windowSec: number; // janela deslizante principal
    ip: number; // limite de requests por IP na janela
    asn: number; // por ASN (por shard)
    fp: number; // por fingerprint TLS derivado (por shard)
    burstWindowSec: number; // janela curta
    ipBurst: number; // limite por IP na janela curta
  };
  geo: { riskCountries: string[] };
  asn: { datacenter: number[]; trusted: number[] }; // extras além da lista embutida
  decoy: { selectors: string[]; replacement: string };
  attestation: { ttlSec: number; challengeGraceSec: number };
  rules: Rule[];
  debugHeader: boolean;
}

export const DEFAULT_RULESET: Ruleset = {
  mode: "monitor",
  weights: {
    asn: 25,
    tls: 15,
    headers: 20,
    ua: 30,
    geo: 10,
    path: 10,
    velocity: 25,
    trap: 45,
    attestation: 30,
  },
  // Calibrado nas fixtures (RESULTS.md): o pior humano plausível (VPN +
  // navegador antigo + proxy corporativo) fica em ~42 (SILENT_VERIFY, que é
  // invisível); DECOY exige >= 2 indicadores fortes independentes (~50+).
  thresholds: { silent_verify: 35, decoy: 50, block: 80 },
  velocity: {
    shards: 4,
    windowSec: 60,
    // IPs de CGNAT/VPN são compartilhados: limites por IP são por página (assets não contam).
    ip: 150,
    asn: 2000,
    fp: 1500,
    burstWindowSec: 5,
    ipBurst: 30,
  },
  geo: { riskCountries: [] },
  asn: { datacenter: [], trusted: [] },
  decoy: {
    selectors: ["[data-ets-decoy]", ".price", ".preco"],
    replacement: "",
  },
  attestation: { ttlSec: 3600, challengeGraceSec: 20 },
  rules: [],
  debugHeader: true,
};

export type ValidationResult = { ok: true; ruleset: Ruleset } | { ok: false; errors: string[] };

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

function numField(
  src: Record<string, unknown>,
  key: string,
  dflt: number,
  errors: string[],
  path: string,
  min = -1000,
  max = 1_000_000,
): number {
  const v = src[key];
  if (v === undefined) return dflt;
  if (typeof v !== "number" || !Number.isFinite(v) || v < min || v > max) {
    errors.push(`${path}.${key}: número entre ${min} e ${max}`);
    return dflt;
  }
  return v;
}

function strArray(v: unknown, errors: string[], path: string): string[] | undefined {
  if (v === undefined) return undefined;
  if (!Array.isArray(v) || !v.every((x) => typeof x === "string")) {
    errors.push(`${path}: lista de strings`);
    return undefined;
  }
  return v as string[];
}

function numArray(v: unknown, errors: string[], path: string): number[] | undefined {
  if (v === undefined) return undefined;
  if (!Array.isArray(v) || !v.every((x) => typeof x === "number")) {
    errors.push(`${path}: lista de números`);
    return undefined;
  }
  return v as number[];
}

const RULE_FIELDS: RuleField[] = ["ip", "asn", "country", "path", "host", "score", "ua"];
const RULE_OPS: RuleOp[] = ["eq", "in", "prefix", "contains", "gte", "lte"];

function validateRules(v: unknown, errors: string[]): Rule[] {
  if (v === undefined) return [];
  if (!Array.isArray(v)) {
    errors.push("rules: lista");
    return [];
  }
  const out: Rule[] = [];
  v.forEach((r, i) => {
    const p = `rules[${i}]`;
    if (!isObj(r) || typeof r.id !== "string" || !isObj(r.if)) {
      errors.push(`${p}: precisa de id, if e verdict`);
      return;
    }
    if (!VERDICTS.includes(r.verdict as Verdict)) {
      errors.push(`${p}.verdict: um de ${VERDICTS.join("|")}`);
      return;
    }
    const c = r.if;
    if (!RULE_FIELDS.includes(c.field as RuleField) || !RULE_OPS.includes(c.op as RuleOp)) {
      errors.push(`${p}.if: field em ${RULE_FIELDS.join("|")} e op em ${RULE_OPS.join("|")}`);
      return;
    }
    const val = c.value;
    const okVal =
      typeof val === "string" ||
      typeof val === "number" ||
      (Array.isArray(val) && val.every((x) => typeof x === "string" || typeof x === "number"));
    if (!okVal) {
      errors.push(`${p}.if.value: string, número ou lista`);
      return;
    }
    out.push({ id: r.id, if: { field: c.field as RuleField, op: c.op as RuleOp, value: val }, verdict: r.verdict as Verdict });
  });
  if (out.length > 200) errors.push("rules: máximo 200");
  return out;
}

// Valida a entrada e completa com defaults. Erros são acumulados, não lançados.
export function validateRuleset(input: unknown): ValidationResult {
  const errors: string[] = [];
  if (!isObj(input)) return { ok: false, errors: ["ruleset precisa ser um objeto"] };
  const d = DEFAULT_RULESET;

  const mode = input.mode === undefined ? d.mode : input.mode;
  if (mode !== "monitor" && mode !== "enforce") errors.push("mode: monitor|enforce");

  const weights = { ...d.weights };
  if (input.weights !== undefined) {
    if (!isObj(input.weights)) errors.push("weights: objeto");
    else {
      for (const [k, v] of Object.entries(input.weights)) {
        if (!SIGNAL_IDS.includes(k as SignalId)) errors.push(`weights.${k}: sinal desconhecido`);
        else if (typeof v !== "number" || !Number.isFinite(v) || v < -100 || v > 100)
          errors.push(`weights.${k}: número entre -100 e 100`);
        else weights[k as SignalId] = v;
      }
    }
  }

  const t = isObj(input.thresholds) ? input.thresholds : {};
  const thresholds = {
    silent_verify: numField(t, "silent_verify", d.thresholds.silent_verify, errors, "thresholds", 0, 100),
    decoy: numField(t, "decoy", d.thresholds.decoy, errors, "thresholds", 0, 100),
    block: numField(t, "block", d.thresholds.block, errors, "thresholds", 0, 101),
  };
  if (!(thresholds.silent_verify <= thresholds.decoy && thresholds.decoy <= thresholds.block))
    errors.push("thresholds: silent_verify <= decoy <= block");

  const v = isObj(input.velocity) ? input.velocity : {};
  const velocity = {
    shards: numField(v, "shards", d.velocity.shards, errors, "velocity", 1, 16),
    windowSec: numField(v, "windowSec", d.velocity.windowSec, errors, "velocity", 5, 300),
    ip: numField(v, "ip", d.velocity.ip, errors, "velocity", 1),
    asn: numField(v, "asn", d.velocity.asn, errors, "velocity", 1),
    fp: numField(v, "fp", d.velocity.fp, errors, "velocity", 1),
    burstWindowSec: numField(v, "burstWindowSec", d.velocity.burstWindowSec, errors, "velocity", 1, 60),
    ipBurst: numField(v, "ipBurst", d.velocity.ipBurst, errors, "velocity", 1),
  };
  if (velocity.burstWindowSec > velocity.windowSec) errors.push("velocity: burstWindowSec <= windowSec");

  const g = isObj(input.geo) ? input.geo : {};
  const geo = { riskCountries: strArray(g.riskCountries, errors, "geo.riskCountries") ?? d.geo.riskCountries };

  const a = isObj(input.asn) ? input.asn : {};
  const asn = {
    datacenter: numArray(a.datacenter, errors, "asn.datacenter") ?? d.asn.datacenter,
    trusted: numArray(a.trusted, errors, "asn.trusted") ?? d.asn.trusted,
  };

  const dc = isObj(input.decoy) ? input.decoy : {};
  const decoy = {
    selectors: strArray(dc.selectors, errors, "decoy.selectors") ?? d.decoy.selectors,
    replacement: typeof dc.replacement === "string" ? dc.replacement : d.decoy.replacement,
  };

  const at = isObj(input.attestation) ? input.attestation : {};
  const attestation = {
    ttlSec: numField(at, "ttlSec", d.attestation.ttlSec, errors, "attestation", 60, 86400 * 7),
    challengeGraceSec: numField(at, "challengeGraceSec", d.attestation.challengeGraceSec, errors, "attestation", 1, 600),
  };

  const rules = validateRules(input.rules, errors);
  const debugHeader = input.debugHeader === undefined ? d.debugHeader : input.debugHeader === true;

  if (errors.length) return { ok: false, errors };
  return {
    ok: true,
    ruleset: { mode: mode as Mode, weights, thresholds, velocity, geo, asn, decoy, attestation, rules, debugHeader },
  };
}

// Parse defensivo do que vem do KV: JSON inválido ou incompleto cai no default.
export function parseStoredRuleset(json: string | null): Ruleset {
  if (!json) return DEFAULT_RULESET;
  try {
    const r = validateRuleset(JSON.parse(json));
    return r.ok ? r.ruleset : DEFAULT_RULESET;
  } catch {
    return DEFAULT_RULESET;
  }
}
