// Utilidades compartilhadas pelos testes.
import { env } from "cloudflare:test";
import { base64urlEncode } from "../src/lib/crypto";
import type { ConnInfo } from "../src/shield/conn";

const enc = new TextEncoder();

export const TEST_EVAL_KEY = "test-eval-key"; // igual ao vitest.config.ts

export async function signEvalContext(
  payload: Record<string, unknown>,
  key: string = TEST_EVAL_KEY,
): Promise<string> {
  const body = enc.encode(JSON.stringify(payload));
  const k = await crypto.subtle.importKey("raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const sig = await crypto.subtle.sign("HMAC", k, body);
  return `${base64urlEncode(body)}.${base64urlEncode(sig)}`;
}

export function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

// Conexão "humana" de referência: Chrome residencial no Brasil, TLS 1.3, h2.
export function humanConn(over: Partial<ConnInfo> = {}): ConnInfo {
  return {
    ip: "177.10.20.30",
    asn: 28573, // Claro
    asOrganization: "Claro NXT Telecomunicacoes",
    country: "BR",
    colo: "GRU",
    tlsVersion: "TLSv1.3",
    tlsCipher: "AEAD-AES128-GCM-SHA256",
    tlsClientHelloLength: 1780,
    httpProtocol: "HTTP/2",
    ...over,
  };
}

export const CHROME_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";

// Headers que um Chrome real manda numa navegação de documento.
export function chromeHeaders(extra: Record<string, string> = {}): Headers {
  return new Headers({
    "user-agent": CHROME_UA,
    accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8",
    "accept-encoding": "gzip, deflate, br, zstd",
    "sec-ch-ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "none",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
    ...extra,
  });
}

export function requestWith(
  url: string,
  headers: Headers | Record<string, string>,
  init: RequestInit = {},
): Request {
  const h = headers instanceof Headers ? headers : new Headers(headers);
  return new Request(url, { ...init, headers: h });
}

export { env };
