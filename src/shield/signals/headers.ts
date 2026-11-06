// Sinal "headers": coerência do conjunto de headers com o navegador alegado.
// Navegadores reais mandam um conjunto previsível (Accept, Accept-Language,
// Sec-Fetch-*, e no Chromium os Client Hints sec-ch-ua*). Ferramentas que
// copiam só o User-Agent erram nesses detalhes.

import { combine, type Signal, type SignalInput, type SignalResult } from "./types";

function brandVersions(secChUa: string): { major: number; brands: string } {
  // '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"'
  let major = 0;
  for (const m of secChUa.matchAll(/"([^"]+)";v="(\d+)"/g)) {
    if (!/not.?a.?brand/i.test(m[1]!)) major = Math.max(major, Number(m[2]));
  }
  return { major, brands: secChUa };
}

function platformOfHint(v: string | null): string {
  return (v ?? "").replace(/"/g, "").toLowerCase();
}

export const headersSignal: Signal = {
  id: "headers",
  passive: true,
  description: "Headers ausentes ou contraditórios para o navegador alegado",
  evaluate(input: SignalInput): SignalResult | null {
    const h = input.headers;
    const ua = input.ua;
    const checks: Array<[number, string]> = [];
    const accept = h.get("accept");
    const lang = h.get("accept-language");
    const encoding = h.get("accept-encoding");
    const secChUa = h.get("sec-ch-ua");
    const fetchMode = h.get("sec-fetch-mode");
    const fetchDest = h.get("sec-fetch-dest");
    const isDoc = fetchDest === "document" || (!fetchDest && accept?.includes("text/html"));

    if (!accept) checks.push([0.6, "no-accept"]);
    if (ua.family === "chrome" || ua.family === "edge" || ua.family === "firefox" || ua.family === "safari") {
      if (!lang) checks.push([0.6, "no-accept-language"]);
      // Navegadores mandam lista com q-values ("pt-BR,pt;q=0.9"); um token só
      // ("en-US") é o default do Playwright/Puppeteer.
      else if (/^[a-z]{2,3}(-[A-Za-z]{2,4})?$/.test(lang.trim())) checks.push([0.5, "single-lang"]);
      if (!encoding) checks.push([0.5, "no-accept-encoding"]);
      if (isDoc && accept && !accept.includes("text/html") && !accept.includes("*/*"))
        checks.push([0.6, "doc-without-html-accept"]);
      if (isDoc && accept === "*/*") checks.push([0.5, "doc-accept-any"]);
      // Sec-Fetch-* existe em Chrome >= 76, Firefox >= 90, Safari >= 16.4.
      if (!fetchMode && ua.major >= 100) checks.push([0.7, "no-sec-fetch"]);
    }
    if ((ua.family === "chrome" || ua.family === "edge") && ua.major >= 90) {
      if (!secChUa) checks.push([0.8, "chromium-without-sec-ch-ua"]);
      else {
        const { major } = brandVersions(secChUa);
        if (/headless/i.test(secChUa)) checks.push([1, "sec-ch-ua-headless"]);
        if (major && Math.abs(major - ua.major) > 1) checks.push([0.9, `brand-mismatch:${major}/${ua.major}`]);
        const mobileHint = h.get("sec-ch-ua-mobile");
        if (mobileHint && (mobileHint === "?1") !== ua.mobile) checks.push([0.7, "mobile-hint-mismatch"]);
        const plat = platformOfHint(h.get("sec-ch-ua-platform"));
        const expected: Record<string, string> = { windows: "windows", macos: "macos", linux: "linux", android: "android", ios: "ios" };
        if (plat && expected[ua.platform] && plat !== expected[ua.platform])
          checks.push([0.9, `platform-mismatch:${plat}/${ua.platform}`]);
      }
    }
    if ((ua.family === "firefox" || ua.family === "safari") && secChUa) checks.push([0.9, "hints-from-non-chromium"]);
    if (ua.family === "empty" || ua.tool) {
      // Ferramenta assumida: o header signal não acrescenta muito além do UA.
      if (!accept || accept === "*/*") checks.push([0.5, "tool-minimal-headers"]);
    }

    return combine(checks) ?? { value: 0, reason: "coherent" };
  },
};
