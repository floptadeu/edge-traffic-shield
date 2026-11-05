// Sinal "geo": país de risco configurado pelo tenant, Tor, país desconhecido
// e, de leve, idioma do navegador incompatível com o país.

import type { Signal, SignalInput, SignalResult } from "./types";

// Idiomas esperados por país (lista curta; só os mais comuns do funil).
const LANGS: Record<string, string[]> = {
  BR: ["pt"], PT: ["pt"], US: ["en", "es"], GB: ["en"], CA: ["en", "fr"], AU: ["en"],
  MX: ["es"], AR: ["es"], CO: ["es"], CL: ["es"], ES: ["es", "ca"], PE: ["es"],
  DE: ["de"], AT: ["de"], FR: ["fr"], IT: ["it"], NL: ["nl"], JP: ["ja"], KR: ["ko"],
  CN: ["zh"], RU: ["ru"], IN: ["en", "hi"],
};

export const geoSignal: Signal = {
  id: "geo",
  passive: true,
  description: "País de risco (tenant), Tor, país desconhecido ou idioma incompatível",
  evaluate(input: SignalInput): SignalResult | null {
    const country = input.conn.country;
    if (!country || country === "XX") return { value: 0.3, reason: "unknown-country" };
    if (country === "T1") return { value: 0.9, reason: "tor" };
    if (input.ruleset.geo.riskCountries.includes(country)) return { value: 0.8, reason: `risk:${country}` };
    const expected = LANGS[country];
    const lang = input.headers.get("accept-language");
    if (expected && lang) {
      const langs = lang.split(",").map((l) => l.trim().slice(0, 2).toLowerCase());
      // "en" é universal o bastante para não penalizar sozinho.
      if (!langs.some((l) => expected.includes(l) || l === "en")) return { value: 0.3, reason: `lang-mismatch:${country}` };
    }
    return { value: 0, reason: country };
  },
};
