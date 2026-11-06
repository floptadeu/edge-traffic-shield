// Parser mínimo de User-Agent + sinal "ua".
// Não tentamos identificar tudo: só o que importa para coerência e automação.

import type { Signal, SignalInput, SignalResult } from "./types";

export type UaFamily = "chrome" | "edge" | "firefox" | "safari" | "other" | "empty";

export interface ParsedUa {
  raw: string;
  family: UaFamily;
  major: number; // versão principal do navegador (0 se desconhecida)
  mobile: boolean;
  platform: "windows" | "macos" | "linux" | "android" | "ios" | "other";
  headless: boolean; // HeadlessChrome, Puppeteer, Playwright, Selenium, PhantomJS
  tool: boolean; // curl, python-requests, Go-http-client...
  botWords: boolean; // "bot", "crawler", "spider" etc.
}

const TOOL_RE =
  /^node$|^node\/|python-requests|python-urllib|aiohttp|httpx|\bcurl\/|\bwget\/|go-http-client|okhttp|axios\/|node-fetch|undici|\bjava\/|apache-httpclient|libwww|scrapy|postmanruntime|insomnia|guzzlehttp|restsharp|\bhttpclient\b|got \(|lwp::|mechanize|phantom|ruby|perl/i;
const HEADLESS_RE = /headlesschrome|puppeteer|playwright|selenium|phantomjs|webdriver|electron/i;
const BOT_RE = /bot\b|crawler|spider|scrap|fetch|monitor|scan|archive|preview|validator/i;

export function parseUserAgent(ua: string | null): ParsedUa {
  const raw = (ua ?? "").trim();
  const p: ParsedUa = {
    raw,
    family: "other",
    major: 0,
    mobile: /mobile|android|iphone|ipad/i.test(raw),
    platform: "other",
    headless: HEADLESS_RE.test(raw),
    tool: TOOL_RE.test(raw),
    botWords: BOT_RE.test(raw),
  };
  if (!raw) {
    p.family = "empty";
    return p;
  }
  if (/windows nt/i.test(raw)) p.platform = "windows";
  else if (/android/i.test(raw)) p.platform = "android";
  else if (/iphone|ipad|ipod/i.test(raw)) p.platform = "ios";
  else if (/mac os x|macintosh/i.test(raw)) p.platform = "macos";
  else if (/linux|x11/i.test(raw)) p.platform = "linux";

  let m: RegExpMatchArray | null;
  if ((m = raw.match(/\bEdg[A-Za-z]*\/(\d+)/))) {
    p.family = "edge";
    p.major = Number(m[1]);
  } else if ((m = raw.match(/\b(?:Chrome|CriOS|HeadlessChrome)\/(\d+)/))) {
    p.family = "chrome";
    p.major = Number(m[1]);
  } else if ((m = raw.match(/\bFirefox\/(\d+)/)) || (m = raw.match(/\bFxiOS\/(\d+)/))) {
    p.family = "firefox";
    p.major = Number(m[1]);
  } else if (/\bSafari\//.test(raw) && (m = raw.match(/\bVersion\/(\d+)/))) {
    p.family = "safari";
    p.major = Number(m[1]);
  }
  return p;
}

export function isBrowser(p: ParsedUa): boolean {
  return p.family !== "other" && p.family !== "empty" && !p.headless;
}

// Faixa plausível de versões de Chromium hoje (ajustar com o tempo).
const CHROME_OLD = 110;
const CHROME_FUTURE = 150;

export const uaSignal: Signal = {
  id: "ua",
  passive: true,
  description: "User-Agent de ferramenta, headless, vazio, implausível ou crawler falso",
  evaluate(input: SignalInput): SignalResult | null {
    const p = parseUserAgent(input.headers.get("user-agent"));
    if (input.crawlerSpoof) return { value: 1, reason: "crawler-ua-not-verified" };
    if (p.family === "empty") return { value: 0.9, reason: "empty" };
    if (p.headless) return { value: 1, reason: "headless" };
    if (p.tool) return { value: 1, reason: "tool" };
    if (p.botWords) return { value: 0.8, reason: "bot-words" };
    if (p.raw.length < 20) return { value: 0.8, reason: "too-short" }; // nenhum navegador tem UA tão curto
    if (/MSIE|Mozilla\/4\.0/.test(p.raw)) return { value: 0.5, reason: "legacy" };
    if ((p.family === "chrome" || p.family === "edge") && p.major > 0) {
      if (p.major < CHROME_OLD) return { value: 0.4, reason: `chrome-old:${p.major}` };
      if (p.major > CHROME_FUTURE) return { value: 0.5, reason: `chrome-future:${p.major}` };
    }
    return { value: 0, reason: "browser" };
  },
};
