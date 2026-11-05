// Informações de conexão usadas pelos sinais. Vêm de request.cf, com
// sobrescrita opcional pelo X-Eval-Context (só quando assinado).

export interface ConnInfo {
  ip: string;
  asn: number;
  asOrganization: string;
  country: string;
  colo: string;
  tlsVersion: string;
  tlsCipher: string;
  tlsClientHelloLength: number;
  httpProtocol: string;
}

// Campos que o avaliador pode sobrescrever (seção 5 do enunciado).
export const EVAL_OVERRIDABLE = [
  "ip",
  "asn",
  "asOrganization",
  "country",
  "tlsVersion",
  "tlsCipher",
  "tlsClientHelloLength",
  "httpProtocol",
] as const;

function num(v: unknown, dflt = 0): number {
  // tlsClientHelloLength chega como string em request.cf e como número no payload de avaliação.
  const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : NaN;
  return Number.isFinite(n) ? n : dflt;
}

function str(v: unknown, dflt = ""): string {
  return typeof v === "string" ? v : dflt;
}

export function connFromRequest(request: Request): ConnInfo {
  const cf = (request.cf ?? {}) as Record<string, unknown>;
  return {
    ip: request.headers.get("cf-connecting-ip") ?? "0.0.0.0",
    asn: num(cf.asn),
    asOrganization: str(cf.asOrganization),
    country: str(cf.country, "XX"),
    colo: str(cf.colo, "LOCAL"),
    tlsVersion: str(cf.tlsVersion),
    tlsCipher: str(cf.tlsCipher),
    tlsClientHelloLength: num(cf.tlsClientHelloLength),
    httpProtocol: str(cf.httpProtocol, "HTTP/1.1"),
  };
}

// Aplica somente os campos presentes e com tipo plausível; o resto fica real.
export function applyOverrides(base: ConnInfo, payload: Record<string, unknown>): ConnInfo {
  const out: ConnInfo = { ...base };
  for (const k of EVAL_OVERRIDABLE) {
    if (!(k in payload) || payload[k] === null || payload[k] === undefined) continue;
    const v = payload[k];
    if (k === "asn" || k === "tlsClientHelloLength") out[k] = num(v, out[k]);
    else out[k] = str(v, out[k]);
  }
  return out;
}
