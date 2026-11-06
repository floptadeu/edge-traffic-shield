// R1 (obrigatório): crawler verificado por rDNS forward-confirmed recebe sempre
// ALLOW, mesmo com ruleset agressivo, regra de BLOCK e velocity estourada.
// Nunca pelo User-Agent: Googlebot falso (sem rDNS) não ganha nada.
import { afterEach, describe, expect, it } from "vitest";
import { crawlerDeps, dohResolver, reverseName, verifyCrawler, type Resolver } from "../src/shield/crawler";
import { CONN, createTenant, debugOf, evalHeader, visit } from "./e2e";

const GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
const BINGBOT_UA = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)";
const FB_UA = "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)";

// Resolvedor falso: só 66.249.66.1 e 40.77.167.1 têm rDNS confirmado.
const fake: Resolver = {
  async ptr(ip) {
    if (ip === "66.249.66.1") return ["crawl-66-249-66-1.googlebot.com"];
    if (ip === "66.249.66.2") return ["crawl-66-249-66-2.googlebot.com"];
    if (ip === "40.77.167.1") return ["msnbot-40-77-167-1.search.msn.com"];
    if (ip === "203.0.113.50") return ["fake-googlebot.evil.example"]; // PTR de outro domínio
    if (ip === "203.0.113.51") return ["crawl-1-2-3-4.googlebot.com"]; // PTR mente: forward não bate
    return [];
  },
  async addr(name) {
    if (name === "crawl-66-249-66-1.googlebot.com") return ["66.249.66.1"];
    if (name === "crawl-66-249-66-2.googlebot.com") return ["66.249.66.2"];
    if (name === "msnbot-40-77-167-1.search.msn.com") return ["40.77.167.1"];
    if (name === "crawl-1-2-3-4.googlebot.com") return ["1.2.3.4"];
    return [];
  },
};

// Ruleset hostil: tudo bloqueia. R1 tem que passar por cima.
const HOSTILE = {
  mode: "enforce" as const,
  thresholds: { silent_verify: 1, decoy: 2, block: 3 },
  rules: [{ id: "block-google-asn", if: { field: "asn" as const, op: "eq" as const, value: 15169 }, verdict: "BLOCK" as const }],
  velocity: { shards: 1, windowSec: 60, ip: 1, asn: 1, fp: 1, burstWindowSec: 5, ipBurst: 1 },
};

afterEach(() => {
  crawlerDeps.resolver = dohResolver;
});

describe("R1 — crawlers verificados", () => {
  it("Googlebot com FCrDNS válido recebe ALLOW apesar de regra BLOCK, limiares mínimos e velocity", async () => {
    crawlerDeps.resolver = fake;
    const t = await createTenant({ ruleset: HOSTILE });
    const ctx = await evalHeader(CONN.aws, { ip: "66.249.66.1", asn: 15169, asOrganization: "Google LLC" });
    for (let i = 0; i < 5; i++) {
      const res = await visit(t.hostname, "/landing", { "user-agent": GOOGLEBOT_UA, accept: "*/*", "x-eval-context": ctx });
      expect(res.status).toBe(200);
      const d = debugOf(res);
      expect(d.applied).toBe("ALLOW");
      expect(d.forced).toContain("verified-crawler:google");
    }
  });

  it("bingbot verificado também; facebookexternalhit verificado pelo AS32934", async () => {
    crawlerDeps.resolver = fake;
    const t = await createTenant({ ruleset: HOSTILE });
    const bing = await visit(t.hostname, "/landing", { "user-agent": BINGBOT_UA, "x-eval-context": await evalHeader(CONN.aws, { ip: "40.77.167.1", asn: 8075 }) });
    expect(debugOf(bing).applied).toBe("ALLOW");
    const fb = await visit(t.hostname, "/landing", { "user-agent": FB_UA, "x-eval-context": await evalHeader(CONN.aws, { ip: "69.171.251.1", asn: 32934, asOrganization: "Facebook" }) });
    expect(debugOf(fb).applied).toBe("ALLOW");
    expect(debugOf(fb).forced).toContain("asn:32934");
  });

  it("User-Agent de Googlebot sem rDNS confirmado NÃO é liberado (e vira sinal de spoof)", async () => {
    crawlerDeps.resolver = fake;
    const t = await createTenant({ ruleset: { mode: "enforce" } });
    for (const ip of ["203.0.113.50", "203.0.113.51", "203.0.113.52"]) {
      const res = await visit(t.hostname, "/landing", { "user-agent": GOOGLEBOT_UA, accept: "*/*", "x-eval-context": await evalHeader(CONN.aws, { ip }) });
      const d = debugOf(res);
      expect(d.forced).toBeUndefined();
      expect(d.signals).toContain("crawler-ua-not-verified");
      expect(d.applied).not.toBe("ALLOW");
    }
  });

  it("DNS indisponível: em dúvida, ALLOW (R1 vale mais que um bot a menos)", async () => {
    crawlerDeps.resolver = { ptr: async () => { throw new Error("doh down"); }, addr: async () => [] };
    const t = await createTenant({ ruleset: HOSTILE });
    const res = await visit(t.hostname, "/landing", { "user-agent": GOOGLEBOT_UA, "x-eval-context": await evalHeader(CONN.aws, { ip: "66.249.66.200", asn: 15169 }) });
    expect(res.status).toBe(200);
    expect(debugOf(res).forced).toContain("crawler-unverifiable");
  });

  it("tenant não consegue sobrescrever R1 (regra BLOCK por UA de crawler é ignorada para verificado)", async () => {
    crawlerDeps.resolver = fake;
    const t = await createTenant({
      ruleset: { mode: "enforce", rules: [{ id: "no-bots", if: { field: "ua", op: "contains", value: "Googlebot" }, verdict: "BLOCK" }] },
    });
    const res = await visit(t.hostname, "/landing", { "user-agent": GOOGLEBOT_UA, "x-eval-context": await evalHeader(CONN.aws, { ip: "66.249.66.1", asn: 15169 }) });
    expect(res.status).toBe(200);
    expect(debugOf(res).applied).toBe("ALLOW");
  });

  it("TikTok/Bytespider sem PTR é 'não verificável' (ALLOW); com PTR de outro domínio é spoof", async () => {
    crawlerDeps.resolver = fake;
    const ua = "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)";
    expect((await verifyCrawler(ua, "47.128.0.9", 16509)).status).toBe("error");
    expect((await verifyCrawler(ua, "203.0.113.50", 16509)).status).toBe("spoofed");
    expect((await verifyCrawler(GOOGLEBOT_UA, "47.128.0.10", 16509)).status).toBe("spoofed");
  });

  it("verifyCrawler isolado: cache positivo evita nova consulta; UA comum não consulta nada", async () => {
    let calls = 0;
    crawlerDeps.resolver = { ptr: async (ip) => { calls++; return fake.ptr(ip); }, addr: fake.addr };
    const a = await verifyCrawler(GOOGLEBOT_UA, "66.249.66.2", 15169);
    const b = await verifyCrawler(GOOGLEBOT_UA, "66.249.66.2", 15169);
    expect(a.status).toBe("verified");
    expect(b.status).toBe("verified");
    expect(calls).toBe(1);
    expect((await verifyCrawler("Mozilla/5.0 Chrome/130", "66.249.66.1", 15169)).status).toBe("none");
  });

  it("reverseName monta in-addr.arpa e ip6.arpa", () => {
    expect(reverseName("66.249.66.1")).toBe("1.66.249.66.in-addr.arpa");
    expect(reverseName("2001:db8::1")).toBe("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa");
  });
});
