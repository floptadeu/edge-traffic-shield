// Origem embutida para demonstração (tenant com origin = "demo").
// Simula a landing page de um cliente com preços, para mostrar DECOY e
// SILENT_VERIFY sem precisar de uma segunda origem publicada.
// Sai em português ou inglês: `?lang=pt|en` manda; sem ele, vale o Accept-Language.

import type { Verdict } from "./ruleset";

type Lang = "pt" | "en";

const TEXT = {
  pt: {
    htmlLang: "pt-BR",
    title: "Curso Pro — landing de demonstração",
    badge: "Loja de demonstração",
    h1: "Curso Pro — turma de novembro",
    lead: "Do zero ao deploy em 12 semanas, com projetos reais e correção individual.",
    pro: "Plano Pro",
    proDesc: "Acesso completo por 12 meses.",
    proPrice: "R$ 1.299,00",
    or: "ou 12x de",
    proInstallment: "R$ 129,90",
    mentor: "Mentoria",
    mentorDesc: "8 encontros ao vivo.",
    mentorPrice: "R$ 4.990,00",
    cta: "Quero me inscrever",
    offers: "API de ofertas",
    aboutTitle: "O que esta página demonstra",
    about:
      "Esta landing simula o site de um cliente. O domínio aponta para o Edge Traffic Shield, que avalia cada requisição na borda antes de entregar a página.",
    verdicts: [
      ["ALLOW", "visitante comum ou crawler verificado: recebe a página real."],
      ["SILENT_VERIFY", "tráfego duvidoso: recebe a página real e uma verificação invisível roda em segundo plano."],
      ["DECOY", "scraper: recebe a mesma página com os preços trocados por valores falsos."],
      ["BLOCK", "abuso evidente: não recebe a página."],
    ],
    applied: "Veredito aplicado nesta resposta",
    debug: "O motivo está no header <code>X-Shield-Debug</code> (DevTools → Network).",
    other: "English",
  },
  en: {
    htmlLang: "en",
    title: "Pro Course — demo landing page",
    badge: "Demo store",
    h1: "Pro Course — November class",
    lead: "From zero to deploy in 12 weeks, with real projects and one-on-one review.",
    pro: "Pro Plan",
    proDesc: "Full access for 12 months.",
    proPrice: "R$ 1,299.00",
    or: "or 12 payments of",
    proInstallment: "R$ 129.90",
    mentor: "Mentoring",
    mentorDesc: "8 live sessions.",
    mentorPrice: "R$ 4,990.00",
    cta: "Enroll now",
    offers: "Offers API",
    aboutTitle: "What this page demonstrates",
    about:
      "This landing page stands in for a customer's site. Its domain points to Edge Traffic Shield, which evaluates every request at the edge before the page is served.",
    verdicts: [
      ["ALLOW", "regular visitor or verified crawler: gets the real page."],
      ["SILENT_VERIFY", "doubtful traffic: gets the real page while an invisible check runs in the background."],
      ["DECOY", "scraper: gets the same page with prices replaced by fake values."],
      ["BLOCK", "obvious abuse: does not get the page."],
    ],
    applied: "Verdict applied to this response",
    debug: "The reason is in the <code>X-Shield-Debug</code> header (DevTools → Network).",
    other: "Português",
  },
} as const;

const CSS =
  "*{box-sizing:border-box}body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:#f6f7f9;color:#1c2330;line-height:1.5}" +
  "main{max-width:760px;margin:0 auto;padding:32px 16px 48px}header{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:24px}" +
  ".badge{font-size:.8em;letter-spacing:.04em;text-transform:uppercase;color:#5b6577}a{color:#1d4ed8}" +
  "h1{font-size:1.9em;line-height:1.2;margin:0 0 8px}h2{font-size:1.15em;margin:0 0 4px}.lead{color:#465064;margin:0 0 24px}" +
  ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px}" +
  ".card{background:#fff;border:1px solid #e1e5ec;border-radius:12px;padding:20px}.card p{margin:4px 0}.price{font-size:1.6em;font-weight:700}" +
  ".cta{display:inline-block;margin:24px 12px 0 0;padding:12px 20px;border-radius:8px;background:#1d4ed8;color:#fff;text-decoration:none;font-weight:600}" +
  ".about{margin-top:40px;padding:20px;border-radius:12px;background:#eef1f6;font-size:.93em}.about ul{padding-left:18px;margin:8px 0}" +
  "code{background:#dde3ee;border-radius:4px;padding:1px 5px;font-size:.95em}.now{font-weight:600}";

function pickLang(url: URL, acceptLanguage: string | null): Lang {
  const q = url.searchParams.get("lang");
  if (q === "en" || q === "pt") return q;
  return acceptLanguage?.trim().toLowerCase().startsWith("en") ? "en" : "pt";
}

export function demoOrigin(url: URL, applied: Verdict, acceptLanguage: string | null = null): Response {
  if (url.pathname === "/api/offers") {
    return Response.json({ offers: [{ sku: "curso-pro", price: 1299 }, { sku: "mentoria", price: 4990 }] });
  }
  if (url.pathname === "/robots.txt") return new Response("User-agent: *\nAllow: /\n", { headers: { "content-type": "text/plain" } });
  const lang = pickLang(url, acceptLanguage);
  const t = TEXT[lang];
  const verdicts = t.verdicts.map(([v, d]) => `<li><code>${v}</code> — ${d}</li>`).join("");
  const html = `<!doctype html>
<html lang="${t.htmlLang}"><head><meta charset="utf-8"><title>${t.title}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>${CSS}</style></head>
<body><main>
<header><span class="badge">${t.badge}</span><a href="?lang=${lang === "pt" ? "en" : "pt"}">${t.other}</a></header>
<h1>${t.h1}</h1>
<p class="lead">${t.lead}</p>
<div class="grid">
<div class="card"><h2>${t.pro}</h2><p>${t.proDesc}</p><p class="price">${t.proPrice}</p><p>${t.or} <span class="price">${t.proInstallment}</span></p></div>
<div class="card"><h2>${t.mentor}</h2><p>${t.mentorDesc}</p><p class="price" data-ets-decoy>${t.mentorPrice}</p></div>
</div>
<p><a class="cta" href="/checkout">${t.cta}</a> <a href="/api/offers">${t.offers}</a></p>
<section class="about"><h2>${t.aboutTitle}</h2>
<p>${t.about}</p>
<ul>${verdicts}</ul>
<p class="now">${t.applied}: <code>${applied}</code></p>
<p>${t.debug}</p></section>
</main></body></html>`;
  return new Response(html, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", vary: "accept-language" } });
}
