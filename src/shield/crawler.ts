// R1: crawlers verificados recebem sempre ALLOW. A verificação é por rede
// (rDNS forward-confirmed via DNS-over-HTTPS, ou ASN publicado pela Meta),
// nunca pelo User-Agent. O UA só decide SE vale gastar a consulta.
// Em dúvida (DNS indisponível) => ALLOW: violar R1 reprova, liberar um bot custa 1.

export type CrawlerFamily = "google" | "bing" | "meta" | "tiktok";
export type CrawlerStatus = "none" | "verified" | "spoofed" | "error";

export interface CrawlerResult {
  status: CrawlerStatus;
  family?: CrawlerFamily;
  via?: string; // rdns:<hostname> | asn:<n> | cache | error:<msg>
}

const CLAIMS: Array<[RegExp, CrawlerFamily]> = [
  [/Googlebot|AdsBot-Google|Mediapartners-Google|Google-InspectionTool|Storebot-Google|APIs-Google/i, "google"],
  [/bingbot|adidxbot|BingPreview/i, "bing"],
  [/facebookexternalhit|facebookcatalog|meta-externalagent|meta-externalfetcher/i, "meta"],
  [/TikTokSpider|Bytespider|ByteDance/i, "tiktok"],
];

// Sufixos de rDNS aceitos por família (documentação pública de cada um).
const RDNS_SUFFIXES: Record<CrawlerFamily, string[]> = {
  google: [".googlebot.com", ".google.com"],
  bing: [".search.msn.com"],
  meta: [".facebook.com", ".fbsv.net", ".tfbnw.net"],
  tiktok: [".tiktok.com", ".bytedance.com", ".byteoversea.com"],
};

// Meta documenta a verificação pelo AS32934 (whois -i origin AS32934).
const ASN_VERIFIED: Partial<Record<CrawlerFamily, number[]>> = { meta: [32934] };

export function claimedCrawler(ua: string | null): CrawlerFamily | null {
  if (!ua) return null;
  for (const [re, fam] of CLAIMS) if (re.test(ua)) return fam;
  return null;
}

// --- resolução DNS (injetável para testes) ----------------------------------

export interface Resolver {
  ptr(ip: string): Promise<string[]>; // nomes do PTR
  addr(hostname: string): Promise<string[]>; // A + AAAA
}

const DOH = "https://cloudflare-dns.com/dns-query";
const DOH_TIMEOUT_MS = 1500;

async function dohQuery(name: string, type: "PTR" | "A" | "AAAA"): Promise<string[]> {
  const url = `${DOH}?name=${encodeURIComponent(name)}&type=${type}`;
  const res = await fetch(url, {
    headers: { accept: "application/dns-json" },
    signal: AbortSignal.timeout(DOH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`doh:${res.status}`);
  const json = (await res.json()) as { Status?: number; Answer?: Array<{ type: number; data: string }> };
  if (json.Status === 3) return []; // NXDOMAIN: resposta válida, só não existe
  if (json.Status !== 0) throw new Error(`doh:status${json.Status}`);
  const want = type === "PTR" ? 12 : type === "A" ? 1 : 28;
  return (json.Answer ?? []).filter((a) => a.type === want).map((a) => a.data.replace(/\.$/, "").toLowerCase());
}

export function reverseName(ip: string): string {
  if (ip.includes(":")) {
    // IPv6: expande e inverte nibble a nibble
    const parts = ip.split("::");
    const head = parts[0] ? parts[0].split(":") : [];
    const tail = parts[1] ? parts[1].split(":") : [];
    const missing = 8 - head.length - tail.length;
    const full = [...head, ...Array(parts.length > 1 ? missing : 0).fill("0"), ...tail].map((h) => h.padStart(4, "0")).join("");
    return `${full.split("").reverse().join(".")}.ip6.arpa`;
  }
  return `${ip.split(".").reverse().join(".")}.in-addr.arpa`;
}

export const dohResolver: Resolver = {
  ptr: (ip) => dohQuery(reverseName(ip), "PTR"),
  addr: async (host) => {
    const [a, aaaa] = await Promise.all([dohQuery(host, "A"), dohQuery(host, "AAAA").catch(() => [] as string[])]);
    return [...a, ...aaaa];
  },
};

// Ponto único de injeção: testes trocam `crawlerDeps.resolver`.
export const crawlerDeps: { resolver: Resolver } = { resolver: dohResolver };

// --- cache -----------------------------------------------------------------
// Memo por isolate + Cache API (por colo, grátis, fora da cota de KV).

interface CacheEntry {
  status: CrawlerStatus;
  via: string;
  exp: number;
}
const memo = new Map<string, CacheEntry>();
const POSITIVE_TTL = 86_400;
const NEGATIVE_TTL = 3_600;

function cacheKey(family: CrawlerFamily, ip: string): string {
  return `https://ets-crawler-cache.internal/${family}/${ip}`;
}

async function cacheGet(family: CrawlerFamily, ip: string): Promise<CacheEntry | null> {
  const k = `${family}/${ip}`;
  const m = memo.get(k);
  if (m && m.exp > Date.now()) return m;
  try {
    const hit = await caches.default.match(cacheKey(family, ip));
    if (!hit) return null;
    const e = (await hit.json()) as CacheEntry;
    memo.set(k, e);
    return e;
  } catch {
    return null;
  }
}

function cachePut(family: CrawlerFamily, ip: string, status: CrawlerStatus, via: string, ctx?: ExecutionContext): void {
  const ttl = status === "verified" ? POSITIVE_TTL : NEGATIVE_TTL;
  const e: CacheEntry = { status, via, exp: Date.now() + ttl * 1000 };
  memo.set(`${family}/${ip}`, e);
  if (memo.size > 5000) memo.clear();
  const p = caches.default
    .put(cacheKey(family, ip), new Response(JSON.stringify(e), { headers: { "cache-control": `max-age=${ttl}` } }))
    .catch(() => {});
  ctx?.waitUntil(p);
}

// --- verificação -------------------------------------------------------------

export async function verifyCrawler(
  ua: string | null,
  ip: string,
  asn: number,
  ctx?: ExecutionContext,
): Promise<CrawlerResult> {
  const family = claimedCrawler(ua);
  if (!family) return { status: "none" };

  const asns = ASN_VERIFIED[family];
  if (asns && asns.includes(asn)) return { status: "verified", family, via: `asn:${asn}` };

  const cached = await cacheGet(family, ip);
  if (cached) return { status: cached.status, family, via: `cache:${cached.via}` };

  try {
    const names = await crawlerDeps.resolver.ptr(ip);
    const suffixes = RDNS_SUFFIXES[family];
    for (const name of names) {
      if (!suffixes.some((s) => name.endsWith(s))) continue;
      const addrs = await crawlerDeps.resolver.addr(name);
      if (addrs.includes(ip.toLowerCase())) {
        cachePut(family, ip, "verified", `rdns:${name}`, ctx);
        return { status: "verified", family, via: `rdns:${name}` };
      }
    }
    cachePut(family, ip, "spoofed", names.length ? `ptr:${names[0]}` : "no-ptr", ctx);
    return { status: "spoofed", family, via: names.length ? `ptr:${names[0]}` : "no-ptr" };
  } catch (err) {
    // Não cacheia erro: tenta de novo no próximo request.
    return { status: "error", family, via: `error:${err instanceof Error ? err.message : String(err)}` };
  }
}
