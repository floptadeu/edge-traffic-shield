// Gera as fixtures rotuladas (fixtures/*.json). Determinístico (seed fixa),
// então o resultado é versionado e reproduzível: `npm run fixtures:gen`.
//
// Método: cada classe é montada a partir de perfis reais observados
// (navegadores, ferramentas, headless) combinados com redes plausíveis
// (ISP residencial, nuvem, VPN, proxy residencial). Inclui de propósito os
// casos difíceis (humano em VPN/navegador antigo; bot com TLS de Chrome em
// IP residencial) para a medida de custo não ser otimista demais.

import { mkdirSync, writeFileSync } from "node:fs";

let seed = 20261105;
const rnd = () => {
  // mulberry32
  seed |= 0;
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const pick = (arr) => arr[Math.floor(rnd() * arr.length)];
const between = (a, b) => a + Math.floor(rnd() * (b - a + 1));
const ipIn = (prefix) => `${prefix}.${between(1, 254)}.${between(1, 254)}`;

// --- redes ------------------------------------------------------------------
const RESIDENTIAL = [
  { asn: 28573, org: "Claro NXT Telecomunicacoes Ltda", country: "BR", prefix: "177.10", lang: "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7" },
  { asn: 27699, org: "TELEFONICA BRASIL S.A", country: "BR", prefix: "179.120", lang: "pt-BR,pt;q=0.9" },
  { asn: 26599, org: "TIM SA", country: "BR", prefix: "189.40", lang: "pt-BR,pt;q=0.8,en;q=0.5" },
  { asn: 53006, org: "Brisanet Servicos de Telecomunicacoes", country: "BR", prefix: "45.160", lang: "pt-BR" },
  { asn: 7922, org: "Comcast Cable Communications, LLC", country: "US", prefix: "73.15", lang: "en-US,en;q=0.9" },
  { asn: 7018, org: "AT&T Services, Inc.", country: "US", prefix: "99.120", lang: "en-US,en;q=0.9,es;q=0.8" },
  { asn: 3243, org: "MEO - SERVICOS DE COMUNICACOES E MULTIMEDIA S.A.", country: "PT", prefix: "85.240", lang: "pt-PT,pt;q=0.9,en;q=0.8" },
  { asn: 8151, org: "Uninet S.A. de C.V.", country: "MX", prefix: "187.190", lang: "es-MX,es;q=0.9" },
  { asn: 7303, org: "Telecom Argentina S.A.", country: "AR", prefix: "181.47", lang: "es-AR,es;q=0.9" },
  { asn: 3320, org: "Deutsche Telekom AG", country: "DE", prefix: "91.20", lang: "de-DE,de;q=0.9,en;q=0.8" },
];
const DATACENTER = [
  { asn: 16509, org: "Amazon.com, Inc.", country: "US", prefix: "3.120" },
  { asn: 14618, org: "Amazon.com, Inc.", country: "US", prefix: "54.90" },
  { asn: 396982, org: "Google LLC", country: "US", prefix: "34.90" },
  { asn: 14061, org: "DigitalOcean, LLC", country: "US", prefix: "164.90" },
  { asn: 24940, org: "Hetzner Online GmbH", country: "DE", prefix: "88.198" },
  { asn: 16276, org: "OVH SAS", country: "FR", prefix: "51.75" },
  { asn: 20473, org: "The Constant Company, LLC", country: "US", prefix: "45.76" },
  { asn: 63949, org: "Akamai Connected Cloud", country: "US", prefix: "172.104" },
  { asn: 45102, org: "Alibaba US Technology Co., Ltd.", country: "SG", prefix: "47.88" },
];
const VPN = [
  { asn: 9009, org: "M247 Europe SRL", country: "NL", prefix: "185.65" },
  { asn: 212238, org: "Datacamp Limited", country: "US", prefix: "89.187" },
];
const RELAY = [{ asn: 13335, org: "Cloudflare, Inc.", country: "BR", prefix: "104.28" }];

// --- pilhas TLS -------------------------------------------------------------
const TLS13 = () => ({ tlsVersion: "TLSv1.3", tlsCipher: pick(["AEAD-AES128-GCM-SHA256", "AEAD-AES256-GCM-SHA384", "AEAD-CHACHA20-POLY1305-SHA256"]) });
const TLS12 = () => ({ tlsVersion: "TLSv1.2", tlsCipher: pick(["ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-CHACHA20-POLY1305"]) });
const stacks = {
  chrome: () => ({ ...TLS13(), tlsClientHelloLength: between(1700, 1950), httpProtocol: pick(["HTTP/2", "HTTP/2", "HTTP/3"]) }),
  firefox: () => ({ ...TLS13(), tlsClientHelloLength: between(1550, 1800), httpProtocol: pick(["HTTP/2", "HTTP/3"]) }),
  safari: () => ({ ...TLS13(), tlsClientHelloLength: between(480, 700), httpProtocol: pick(["HTTP/2", "HTTP/3"]) }),
  oldChrome: () => ({ ...TLS12(), tlsClientHelloLength: between(500, 560), httpProtocol: "HTTP/2" }),
  python: () => ({ ...TLS13(), tlsClientHelloLength: between(290, 420), httpProtocol: "HTTP/1.1" }),
  curl: () => ({ ...TLS13(), tlsClientHelloLength: between(330, 520), httpProtocol: pick(["HTTP/2", "HTTP/1.1"]) }),
  go: () => ({ ...TLS13(), tlsClientHelloLength: between(230, 330), httpProtocol: "HTTP/2" }),
  node: () => ({ ...TLS13(), tlsClientHelloLength: between(320, 450), httpProtocol: "HTTP/1.1" }),
  java: () => ({ ...TLS12(), tlsClientHelloLength: between(200, 330), httpProtocol: "HTTP/1.1" }),
  impersonate: () => ({ ...TLS13(), tlsClientHelloLength: between(1700, 1900), httpProtocol: "HTTP/2" }), // curl-impersonate / tls-client
};

// --- navegadores --------------------------------------------------------------
const CH = (v, platform, mobile = false) => ({
  "sec-ch-ua": `"Chromium";v="${v}", "Google Chrome";v="${v}", "Not?A_Brand";v="99"`,
  "sec-ch-ua-mobile": mobile ? "?1" : "?0",
  "sec-ch-ua-platform": `"${platform}"`,
});
const NAV = (accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8") => ({
  accept,
  "accept-encoding": "gzip, deflate, br, zstd",
  "sec-fetch-dest": "document",
  "sec-fetch-mode": "navigate",
  "sec-fetch-site": pick(["none", "none", "cross-site", "same-origin"]),
  "sec-fetch-user": "?1",
  "upgrade-insecure-requests": "1",
});
const browsers = [
  {
    name: "Chrome Windows",
    stack: "chrome",
    make: () => {
      const v = between(128, 142);
      return { "user-agent": `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36`, ...NAV(), ...CH(v, "Windows") };
    },
  },
  {
    name: "Chrome macOS",
    stack: "chrome",
    make: () => {
      const v = between(128, 142);
      return { "user-agent": `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36`, ...NAV(), ...CH(v, "macOS") };
    },
  },
  {
    name: "Chrome Android",
    stack: "chrome",
    make: () => {
      const v = between(128, 142);
      return { "user-agent": `Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Mobile Safari/537.36`, ...NAV(), ...CH(v, "Android", true) };
    },
  },
  {
    name: "Edge Windows",
    stack: "chrome",
    make: () => {
      const v = between(128, 142);
      return { "user-agent": `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36 Edg/${v}.0.0.0`, ...NAV(), "sec-ch-ua": `"Chromium";v="${v}", "Microsoft Edge";v="${v}", "Not?A_Brand";v="99"`, "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Windows"' };
    },
  },
  {
    name: "Firefox Windows",
    stack: "firefox",
    make: () => {
      const v = between(128, 146);
      return { "user-agent": `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${v}.0) Gecko/20100101 Firefox/${v}.0`, ...NAV("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8") };
    },
  },
  {
    name: "Safari macOS",
    stack: "safari",
    make: () => ({ "user-agent": `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${pick([17, 18])}.${between(0, 5)} Safari/605.1.15`, ...NAV("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8") }),
  },
  {
    name: "Safari iPhone",
    stack: "safari",
    make: () => ({ "user-agent": `Mozilla/5.0 (iPhone; CPU iPhone OS 18_${between(0, 6)} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.${between(0, 6)} Mobile/15E148 Safari/604.1`, ...NAV("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8") }),
  },
];

const ctxOf = (net, stack) => ({ ip: ipIn(net.prefix), asn: net.asn, asOrganization: net.org, country: net.country, ...stacks[stack]() });
const PATHS = ["/landing", "/landing", "/", "/oferta", "/checkout", "/landing?utm_source=google&utm_medium=cpc", "/api/offers"];

// --- humanos -------------------------------------------------------------------
function humans(n) {
  const out = [];
  for (let i = 0; i < n; i++) {
    const b = pick(browsers);
    const net = pick(RESIDENTIAL);
    const headers = { ...b.make(), "accept-language": net.lang };
    let ctx = ctxOf(net, b.stack);
    let note = `${b.name} em ${net.org} (${net.country})`;
    const r = rnd();
    if (r < 0.1) {
      const v = pick(VPN);
      ctx = { ...ctx, ip: ipIn(v.prefix), asn: v.asn, asOrganization: v.org, country: v.country };
      note += " via VPN comercial";
    } else if (r < 0.15) {
      ctx = { ...ctx, ...stacks.oldChrome() };
      headers["user-agent"] = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36";
      Object.assign(headers, CH(109, "Windows"));
      note = "Chrome 109 no Windows 7 (TLS 1.2) em " + net.org;
    } else if (r < 0.2) {
      ctx = { ...ctx, httpProtocol: "HTTP/1.1" };
      note += " atrás de proxy corporativo (HTTP/1.1)";
    } else if (r < 0.25) {
      const relay = RELAY[0];
      ctx = { ...ctx, ip: ipIn(relay.prefix), asn: relay.asn, asOrganization: relay.org };
      note += " via iCloud Private Relay/WARP";
    } else if (r < 0.3) {
      headers["accept-language"] = pick(["en-US,en;q=0.9", "zh-CN,zh;q=0.9", "ru-RU,ru;q=0.9"]);
      note += " com Accept-Language de outro país";
    }
    out.push({ id: `human-${String(i + 1).padStart(3, "0")}`, label: "human", expect: "ALLOW", note, path: pick(PATHS), ctx, headers });
  }
  return out;
}

// --- scrapers -----------------------------------------------------------------
const TOOLS = [
  { ua: () => `python-requests/2.${between(28, 33)}.0`, stack: "python", headers: { accept: "*/*", "accept-encoding": "gzip, deflate" } },
  { ua: () => `python-httpx/0.${between(25, 28)}.0`, stack: "python", headers: { accept: "*/*", "accept-encoding": "gzip, deflate, br" } },
  { ua: () => `curl/8.${between(1, 11)}.0`, stack: "curl", headers: { accept: "*/*" } },
  { ua: () => "Go-http-client/2.0", stack: "go", headers: { accept: "*/*", "accept-encoding": "gzip" } },
  { ua: () => `Scrapy/2.${between(9, 13)} (+https://scrapy.org)`, stack: "python", headers: { accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "accept-language": "en", "accept-encoding": "gzip, deflate, br" } },
  { ua: () => `axios/1.${between(5, 9)}.0`, stack: "node", headers: { accept: "application/json, text/plain, */*", "accept-encoding": "gzip, compress, deflate, br" } },
  { ua: () => `Java/17.0.${between(5, 12)}`, stack: "java", headers: { accept: "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2" } },
  { ua: () => "", stack: "python", headers: { accept: "*/*" } },
];
function scrapers(n) {
  const out = [];
  for (let i = 0; i < n; i++) {
    const r = rnd();
    let fx;
    if (r < 0.45) {
      // ferramenta crua em nuvem
      const t = pick(TOOLS);
      const net = pick(DATACENTER);
      const ua = t.ua();
      fx = { note: `${ua || "UA vazio"} em ${net.org}`, ctx: ctxOf(net, t.stack), headers: { ...(ua ? { "user-agent": ua } : {}), ...t.headers } };
    } else if (r < 0.7) {
      // UA de Chrome colado em cliente HTTP (sem client hints, HTTP/1.1, hello curto)
      const net = pick(DATACENTER);
      const v = between(120, 141);
      fx = {
        note: `requests com UA de Chrome ${v} em ${net.org}`,
        ctx: ctxOf(net, pick(["python", "node"])),
        headers: { "user-agent": `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36`, accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "accept-language": "en-US,en;q=0.9", "accept-encoding": "gzip, deflate" },
      };
    } else if (r < 0.85) {
      // headers completos copiados do DevTools, mas pilha TLS de Python/Go
      const b = browsers[0];
      const net = pick(DATACENTER);
      fx = { note: `headers de ${b.name} copiados, TLS de httpx, em ${net.org}`, ctx: ctxOf(net, pick(["python", "go"])), headers: { ...b.make(), "accept-language": "en-US,en;q=0.9" } };
    } else {
      // curl-impersonate / tls-client: TLS idêntico ao Chrome; metade em proxy residencial
      const b = pick(browsers.slice(0, 2));
      const net = rnd() < 0.5 ? pick(DATACENTER) : pick(RESIDENTIAL);
      fx = { note: `curl-impersonate (TLS de Chrome) em ${net.org}${net.lang ? " (proxy residencial)" : ""}`, ctx: ctxOf(net, "impersonate"), headers: { ...b.make(), "accept-language": "en-US,en;q=0.9" } };
    }
    out.push({ id: `scraper-${String(i + 1).padStart(3, "0")}`, label: "scraper", expect: "DENY", path: pick(PATHS), ...fx });
  }
  return out;
}

// --- headless --------------------------------------------------------------------
function headless(n) {
  const out = [];
  for (let i = 0; i < n; i++) {
    const r = rnd();
    const v = between(126, 141);
    let fx;
    if (r < 0.4) {
      const net = pick(DATACENTER);
      fx = {
        note: `Playwright headless shell (HeadlessChrome/${v}) em ${net.org}`,
        ctx: ctxOf(net, "chrome"),
        headers: { "user-agent": `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/${v}.0.0.0 Safari/537.36`, ...NAV(), "accept-language": "en-US", "sec-ch-ua": `"HeadlessChrome";v="${v}", "Chromium";v="${v}", "Not?A_Brand";v="99"`, "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Linux"' },
      };
    } else if (r < 0.65) {
      // UA sobrescrito para Chrome normal, mas hints ainda entregam (brand headless / plataforma Linux vs UA Windows)
      const net = pick(DATACENTER);
      fx = {
        note: `headless com UA de Chrome Windows mas sec-ch-ua-platform Linux em ${net.org}`,
        ctx: ctxOf(net, "chrome"),
        headers: { "user-agent": `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${v}.0.0.0 Safari/537.36`, ...NAV(), "accept-language": "en-US,en;q=0.9", ...CH(v, "Linux") },
      };
    } else if (r < 0.85) {
      // stealth consistente em nuvem: só o ASN entrega
      const net = pick(DATACENTER);
      fx = { note: `Playwright + stealth (hints consistentes) em ${net.org}`, ctx: ctxOf(net, "chrome"), headers: { ...browsers[0].make(), "accept-language": "en-US,en;q=0.9" } };
    } else {
      // stealth + proxy residencial: indistinguível por sinal passivo (vai custar 1 ponto cada)
      const net = pick(RESIDENTIAL);
      fx = { note: `Playwright + stealth + proxy residencial ${net.org}`, ctx: ctxOf(net, "chrome"), headers: { ...browsers[0].make(), "accept-language": net.lang } };
    }
    out.push({ id: `headless-${String(i + 1).padStart(3, "0")}`, label: "headless", expect: "DENY", path: pick(PATHS), ...fx });
  }
  return out;
}

// --- crawlers verificados -----------------------------------------------------------
// IPs reais com rDNS forward-confirmed (a avaliação local consulta DoH de verdade).
const CRAWLERS = [
  { ua: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", ips: ["66.249.66.1", "66.249.66.9", "66.249.66.33", "66.249.70.1", "66.249.79.1"], asn: 15169, org: "Google LLC" },
  { ua: "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", ips: ["66.249.66.65", "66.249.66.67", "66.249.64.1"], asn: 15169, org: "Google LLC" },
  { ua: "AdsBot-Google (+http://www.google.com/adsbot.html)", ips: ["66.249.66.129", "66.249.66.161"], asn: 15169, org: "Google LLC" },
  { ua: "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", ips: ["40.77.167.1", "40.77.167.33", "207.46.13.1", "157.55.39.1"], asn: 8075, org: "Microsoft Corporation" },
  { ua: "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", ips: ["69.171.251.1", "173.252.95.5", "66.220.149.9"], asn: 32934, org: "Facebook, Inc." },
  { ua: "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)", ips: ["110.249.201.1", "111.225.148.1"], asn: 4134, org: "Chinanet" },
];
function crawlers() {
  const out = [];
  let i = 0;
  for (const c of CRAWLERS) {
    for (const ip of c.ips) {
      out.push({
        id: `crawler-${String(++i).padStart(3, "0")}`,
        label: "crawler",
        expect: "ALLOW",
        note: `${c.ua.split(" (")[0].split("/")[0]} de ${ip} (verificação por rede, não por UA)`,
        path: pick(["/", "/landing", "/robots.txt", "/sitemap.xml"]),
        ctx: { ip, asn: c.asn, asOrganization: c.org, country: "US", tlsVersion: "TLSv1.3", tlsCipher: "AEAD-AES128-GCM-SHA256", tlsClientHelloLength: between(400, 600), httpProtocol: pick(["HTTP/1.1", "HTTP/2"]) },
        headers: { "user-agent": c.ua, accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "accept-encoding": "gzip, deflate, br", from: c.ua.includes("google") ? "googlebot(at)googlebot.com" : undefined },
      });
    }
  }
  for (const fx of out) if (fx.headers.from === undefined) delete fx.headers.from;
  return out;
}

mkdirSync("fixtures", { recursive: true });
const sets = { human: humans(160), scraper: scrapers(120), headless: headless(80), crawler: crawlers() };
for (const [name, list] of Object.entries(sets)) {
  writeFileSync(`fixtures/${name}.json`, JSON.stringify(list, null, 1) + "\n");
  console.log(`fixtures/${name}.json: ${list.length}`);
}
