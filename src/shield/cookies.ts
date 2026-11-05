// Cookies assinados (HMAC) para a atestação assíncrona.
//   __ets_c   : desafio emitido em SILENT_VERIFY  { iat, n }
//   __ets_att : atestação concluída pelo beacon    { exp, fp, k }
// A atestação é amarrada ao fingerprint derivado: um cookie obtido num
// navegador real não serve num python-requests do mesmo IP.

import { base64urlDecode, base64urlEncode, hmacSha256, timingSafeEqual } from "../lib/crypto";
import type { AttestationState } from "./signals";

export const CHALLENGE_COOKIE = "__ets_c";
export const ATTEST_COOKIE = "__ets_att";

const enc = new TextEncoder();

export function parseCookies(header: string | null): Map<string, string> {
  const out = new Map<string, string>();
  if (!header) return out;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i <= 0) continue;
    out.set(part.slice(0, i).trim(), part.slice(i + 1).trim());
  }
  return out;
}

export async function signValue(secret: string, payload: Record<string, unknown>): Promise<string> {
  const body = enc.encode(JSON.stringify(payload));
  const sig = await hmacSha256(secret, body);
  return `${base64urlEncode(body)}.${base64urlEncode(sig)}`;
}

export async function verifyValue(secret: string, value: string | undefined): Promise<Record<string, unknown> | null> {
  if (!value) return null;
  const dot = value.indexOf(".");
  if (dot <= 0) return null;
  const body = base64urlDecode(value.slice(0, dot));
  const sig = base64urlDecode(value.slice(dot + 1));
  if (!body || !sig) return null;
  const expected = await hmacSha256(secret, body);
  if (!timingSafeEqual(expected, sig)) return null;
  try {
    const obj = JSON.parse(new TextDecoder().decode(body)) as unknown;
    return typeof obj === "object" && obj !== null ? (obj as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export interface ChallengePayload extends Record<string, unknown> {
  iat: number; // epoch s
  n: string; // nonce
}

export async function readAttestation(
  cookieHeader: string | null,
  secret: string,
  fingerprint: string,
  nowSec: number,
): Promise<{ state: AttestationState; challenge?: ChallengePayload }> {
  const cookies = parseCookies(cookieHeader);
  const att = await verifyValue(secret, cookies.get(ATTEST_COOKIE));
  if (att && typeof att.exp === "number" && att.exp > nowSec && att.fp === fingerprint) {
    return { state: { kind: "attested" } };
  }
  const ch = await verifyValue(secret, cookies.get(CHALLENGE_COOKIE));
  if (ch && typeof ch.iat === "number" && typeof ch.n === "string") {
    const ageSec = Math.max(0, nowSec - ch.iat);
    // Desafio muito antigo (> 1 dia) é descartado: emite outro.
    if (ageSec < 86_400) return { state: { kind: "challenged", ageSec }, challenge: { iat: ch.iat, n: ch.n } };
  }
  return { state: { kind: "none" } };
}

export function cookieHeader(name: string, value: string, maxAgeSec: number): string {
  return `${name}=${value}; Path=/; Max-Age=${maxAgeSec}; Secure; HttpOnly; SameSite=Lax`;
}

export function clearCookieHeader(name: string): string {
  return `${name}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax`;
}
