// Sinal "tls": fingerprint TLS *derivado* dos campos padrão de request.cf
// (sem Bot Management). A ideia é coerência: um "Chrome 130" que negocia
// TLS 1.2, HTTP/1.1, cifra CBC ou manda um ClientHello de 300 bytes não é Chrome.

import { fnv1a } from "../../lib/crypto";
import type { ConnInfo } from "../conn";
import { isBrowser, parseUserAgent, type ParsedUa } from "./ua";
import { combine, type Signal, type SignalInput, type SignalResult } from "./types";

// Fingerprint estável usado como chave de velocity. Não identifica uma pessoa;
// agrupa clientes com a mesma pilha TLS/HTTP/UA.
export function deriveFingerprint(conn: ConnInfo, ua: ParsedUa): string {
  const bucket = Math.floor(conn.tlsClientHelloLength / 64);
  const key = `${conn.tlsVersion}|${conn.tlsCipher}|${bucket}|${conn.httpProtocol}|${ua.family}|${ua.major}|${ua.platform}`;
  return fnv1a(key).toString(36);
}

function isCbcCipher(cipher: string): boolean {
  if (!cipher) return false;
  const c = cipher.toUpperCase();
  return !/GCM|CHACHA|POLY1305|CCM|AEAD/.test(c) && /SHA/.test(c);
}

export const tlsSignal: Signal = {
  id: "tls",
  passive: true,
  description: "Incoerência entre o navegador alegado e a pilha TLS/HTTP negociada",
  evaluate(input: SignalInput): SignalResult | null {
    const { tlsVersion, tlsCipher, tlsClientHelloLength: len, httpProtocol } = input.conn;
    if (!tlsVersion && !httpProtocol) return null; // sem dados (ex.: teste local em http)
    const ua = parseUserAgent(input.headers.get("user-agent"));
    const browser = isBrowser(ua);
    const checks: Array<[number, string]> = [];

    if (tlsVersion && /TLSv1(\.0|\.1)?$|SSLv/.test(tlsVersion)) checks.push([1, `legacy-tls:${tlsVersion}`]);

    if (browser) {
      // Chrome >= 70, Firefox >= 63, Safari >= 12.1 e Edge Chromium só negociam 1.2 se 1.3 não existir.
      if (tlsVersion === "TLSv1.2") checks.push([0.6, "browser-tls1.2"]);
      // Todo navegador moderno fala h2 (ou h3) com a Cloudflare.
      if (httpProtocol === "HTTP/1.1" || httpProtocol === "HTTP/1.0") checks.push([0.7, `browser-${httpProtocol}`]);
      if (isCbcCipher(tlsCipher)) checks.push([0.8, "cbc-cipher"]);
      // ClientHello curto demais para um navegador atual (GREASE, ALPN, ML-KEM...).
      // Chrome não manda menos de ~500 bytes desde 2016: é quase decisivo.
      if (len > 0) {
        if ((ua.family === "chrome" || ua.family === "edge") && len < 500) checks.push([0.9, `short-hello:${len}`]);
        else if (ua.family === "firefox" && len < 350) checks.push([0.8, `short-hello:${len}`]);
        else if (len < 200) checks.push([0.6, `short-hello:${len}`]);
      }
    } else if (isCbcCipher(tlsCipher)) {
      checks.push([0.4, "cbc-cipher"]);
    }

    return combine(checks) ?? { value: 0, reason: "coherent" };
  },
};
