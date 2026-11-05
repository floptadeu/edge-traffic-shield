// Primitivas de criptografia usadas no hot path e na API.
// Tudo via WebCrypto (nativo no runtime Workers, sem dependência).

const enc = new TextEncoder();

export function base64urlEncode(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (const b of u8) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlDecode(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  try {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

// Cache de chaves HMAC importadas por isolate: importKey custa ~0,1 ms e
// o mesmo segredo é usado em todo request.
const keyCache = new Map<string, Promise<CryptoKey>>();

export function hmacKey(secret: string): Promise<CryptoKey> {
  let p = keyCache.get(secret);
  if (!p) {
    p = crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
    ]);
    keyCache.set(secret, p);
  }
  return p;
}

export async function hmacSha256(secret: string, data: string | Uint8Array): Promise<Uint8Array> {
  const key = await hmacKey(secret);
  const bytes = typeof data === "string" ? enc.encode(data) : data;
  const sig = await crypto.subtle.sign("HMAC", key, bytes as BufferSource);
  return new Uint8Array(sig);
}

export async function hmacSha256Base64url(secret: string, data: string): Promise<string> {
  return base64urlEncode(await hmacSha256(secret, data));
}

// Comparação em tempo constante. crypto.subtle.timingSafeEqual exige tamanhos
// iguais; tamanhos diferentes já são "falso" sem vazar nada além do tamanho.
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  return crypto.subtle.timingSafeEqual(a as BufferSource, b as BufferSource);
}

export async function sha256Hex(data: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(data));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function randomToken(bytes = 24): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return base64urlEncode(buf);
}

// Hash não criptográfico e barato (FNV-1a 32 bits) para escolher shard e
// anonimizar IP em agregados. Não é segredo, é só distribuição.
export function fnv1a(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}
