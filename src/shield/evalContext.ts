// Contrato X-Eval-Context (seção 5 do enunciado).
//   X-Eval-Context: <base64url(payload)>.<base64url(HMAC-SHA256(payload, EVAL_KEY))>
// Regras: só aceita com assinatura válida (tempo constante) e |now - iat| <= 300 s.
// Qualquer problema => ignora em silêncio e segue com request.cf real.

import { base64urlDecode, hmacSha256, timingSafeEqual } from "../lib/crypto";
import { applyOverrides, type ConnInfo } from "./conn";

export const EVAL_IAT_WINDOW_SEC = 300;

export type EvalContextResult =
  | { status: "absent" }
  | { status: "rejected"; reason: string }
  | { status: "accepted"; conn: ConnInfo };

export async function applyEvalContext(
  header: string | null,
  evalKey: string | undefined,
  real: ConnInfo,
  nowSec: number = Math.floor(Date.now() / 1000),
): Promise<EvalContextResult> {
  if (!header) return { status: "absent" };
  // Sem chave configurada não existe como verificar; portanto não aceita.
  if (!evalKey) return { status: "rejected", reason: "no-key" };

  const dot = header.indexOf(".");
  if (dot <= 0 || dot === header.length - 1) return { status: "rejected", reason: "format" };
  const payloadB64 = header.slice(0, dot);
  const sigB64 = header.slice(dot + 1);

  const payloadBytes = base64urlDecode(payloadB64);
  const sigBytes = base64urlDecode(sigB64);
  if (!payloadBytes || !sigBytes) return { status: "rejected", reason: "base64" };

  // A assinatura é sobre os bytes do payload (antes do base64), conforme o contrato.
  let expected: Uint8Array;
  try {
    expected = await hmacSha256(evalKey, payloadBytes);
  } catch {
    return { status: "rejected", reason: "hmac" };
  }
  if (!timingSafeEqual(expected, sigBytes)) return { status: "rejected", reason: "signature" };

  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch {
    return { status: "rejected", reason: "json" };
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return { status: "rejected", reason: "json" };
  }
  const obj = payload as Record<string, unknown>;
  const iat = typeof obj.iat === "number" ? obj.iat : NaN;
  if (!Number.isFinite(iat) || Math.abs(nowSec - iat) > EVAL_IAT_WINDOW_SEC) {
    return { status: "rejected", reason: "iat" };
  }

  return { status: "accepted", conn: applyOverrides(real, obj) };
}
