// Origem embutida para demonstração (tenant com origin = "demo").
// Simula a landing page de um cliente com preços, para mostrar DECOY e
// SILENT_VERIFY sem precisar de uma segunda origem publicada.
// A página sai em inglês; `?lang=pt` entrega a versão em português.

import type { Verdict } from "./ruleset";

type Lang = "pt" | "en";

const TEXT = {
  en: {
    htmlLang: "en",
    title: "Pro Course — demo landing page",
    brand: "Demo Store",
    tag: "Protected by Edge Traffic Shield",
    kicker: "November class · enrollment open",
    h1: "Ship production backends in 12 weeks",
    lead: "A hands-on course with real projects, code review on every delivery and a small class.",
    pro: "Pro Plan",
    proDesc: "Everything you need to go from zero to deploy.",
    proItems: ["Full access for 12 months", "12 real projects with review", "Private community"],
    proPrice: "$1,299.00",
    or: "or 12 payments of",
    proInstallment: "$129.90",
    popular: "Most popular",
    mentor: "Mentoring",
    mentorDesc: "For people who want to go faster, with a senior engineer.",
    mentorItems: ["8 live one-on-one sessions", "Career and architecture review", "Everything in the Pro Plan"],
    mentorPrice: "$4,990.00",
    cta: "Enroll now",
    offers: "Offers API (JSON)",
    aboutTitle: "What this page demonstrates",
    about:
      "This landing page stands in for a customer's site. Its domain points to Edge Traffic Shield, which scores every request at the edge and picks one of four verdicts before the page is served.",
    verdicts: [
      ["ALLOW", "Regular visitor or verified crawler. Gets the real page."],
      ["SILENT_VERIFY", "Doubtful traffic. Gets the real page while an invisible check runs in the background."],
      ["DECOY", "Scraper. Gets the same page with the prices replaced by fake values."],
      ["BLOCK", "Obvious abuse. Does not get the page."],
    ],
    applied: "Verdict applied to this response",
    tryTitle: "Try it yourself",
    try1: "<b>As a person.</b> You are doing it now. Open DevTools (F12) → Network, reload, click the first request and read the <code>X-Shield-Debug</code> response header: verdict, score and the signals behind it.",
    try2: "<b>As a scraper.</b> Run this in a terminal. The score goes up because of the tool User-Agent and the missing browser headers; from a datacenter IP it reaches <code>DECOY</code> and the prices in the HTML are fake.",
    try3: "<b>Deterministic, with a signed context.</b> From the repository, with <code>EVAL_KEY</code> set, this simulates a client on a cloud network and prints the prices it received.",
    other: "Português",
    foot: "Demo content. No real product is sold on this page.",
  },
  pt: {
    htmlLang: "pt-BR",
    title: "Curso Pro — landing de demonstração",
    brand: "Loja Demo",
    tag: "Protegida pelo Edge Traffic Shield",
    kicker: "Turma de novembro · inscrições abertas",
    h1: "Coloque backends em produção em 12 semanas",
    lead: "Curso prático com projetos reais, revisão de código em toda entrega e turma pequena.",
    pro: "Plano Pro",
    proDesc: "Tudo para sair do zero e chegar ao deploy.",
    proItems: ["Acesso completo por 12 meses", "12 projetos reais com revisão", "Comunidade privada"],
    proPrice: "R$ 1.299,00",
    or: "ou 12x de",
    proInstallment: "R$ 129,90",
    popular: "Mais escolhido",
    mentor: "Mentoria",
    mentorDesc: "Para quem quer ir mais rápido, com um engenheiro sênior.",
    mentorItems: ["8 encontros individuais ao vivo", "Revisão de carreira e arquitetura", "Tudo do Plano Pro"],
    mentorPrice: "R$ 4.990,00",
    cta: "Quero me inscrever",
    offers: "API de ofertas (JSON)",
    aboutTitle: "O que esta página demonstra",
    about:
      "Esta landing simula o site de um cliente. O domínio aponta para o Edge Traffic Shield, que pontua cada requisição na borda e escolhe um de quatro vereditos antes de entregar a página.",
    verdicts: [
      ["ALLOW", "Visitante comum ou crawler verificado. Recebe a página real."],
      ["SILENT_VERIFY", "Tráfego duvidoso. Recebe a página real e uma verificação invisível roda em segundo plano."],
      ["DECOY", "Scraper. Recebe a mesma página com os preços trocados por valores falsos."],
      ["BLOCK", "Abuso evidente. Não recebe a página."],
    ],
    applied: "Veredito aplicado nesta resposta",
    tryTitle: "Teste você mesmo",
    try1: "<b>Como pessoa.</b> É o que você está fazendo agora. Abra o DevTools (F12) → Network, recarregue, clique na primeira requisição e leia o header de resposta <code>X-Shield-Debug</code>: veredito, score e os sinais que pesaram.",
    try2: "<b>Como scraper.</b> Rode no terminal. O score sobe por causa do User-Agent de ferramenta e dos headers de navegador ausentes; de um IP de datacenter chega a <code>DECOY</code> e os preços no HTML são falsos.",
    try3: "<b>Determinístico, com contexto assinado.</b> No repositório, com <code>EVAL_KEY</code> definida, simula um cliente em rede de nuvem e imprime os preços recebidos.",
    other: "English",
    foot: "Conteúdo de demonstração. Nenhum produto real é vendido nesta página.",
  },
} as const;

const CSS =
  ":root{--ink:#0f172a;--mut:#5b6577;--line:#e3e7ee;--bg:#f5f7fb;--pri:#4f46e5;--pri2:#7c3aed}" +
  "*{box-sizing:border-box}body{font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;margin:0;background:var(--bg);color:var(--ink);line-height:1.55}" +
  "a{color:var(--pri)}.wrap{max-width:960px;margin:0 auto;padding:0 20px}" +
  ".hero{background:linear-gradient(135deg,#0f172a 0%,#312e81 55%,#6d28d9 100%);color:#fff;padding:0 0 120px}" +
  "nav{display:flex;justify-content:space-between;align-items:center;padding:22px 0}.brand{font-weight:800;font-size:1.1em;letter-spacing:-.01em}" +
  ".brand i{display:inline-block;width:10px;height:10px;border-radius:3px;background:#a5b4fc;margin-right:8px}" +
  "nav a{color:#e0e7ff;text-decoration:none;font-size:.9em;border:1px solid rgba(255,255,255,.3);border-radius:999px;padding:6px 14px}" +
  ".kicker{display:inline-block;margin-top:44px;font-size:.8em;letter-spacing:.06em;text-transform:uppercase;background:rgba(255,255,255,.12);border-radius:999px;padding:6px 14px}" +
  "h1{font-size:clamp(2em,5vw,3.1em);line-height:1.1;letter-spacing:-.02em;margin:18px 0 14px;max-width:16ch}" +
  ".lead{font-size:1.15em;color:#dbe1ff;max-width:52ch;margin:0}.tag{margin-top:22px;font-size:.85em;color:#c7d2fe}" +
  ".plans{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:20px;margin-top:-84px}" +
  ".card{position:relative;background:#fff;border:1px solid var(--line);border-radius:16px;padding:28px;box-shadow:0 10px 30px rgba(15,23,42,.08)}" +
  ".card.hot{border:2px solid var(--pri)}.pop{position:absolute;top:-12px;right:20px;background:var(--pri);color:#fff;font-size:.75em;font-weight:700;border-radius:999px;padding:4px 12px}" +
  "h2{font-size:1.25em;margin:0 0 4px}.card p{margin:4px 0;color:var(--mut)}.card ul{list-style:none;padding:0;margin:16px 0}" +
  ".card li{padding:5px 0 5px 26px;position:relative}.card li:before{content:'✓';position:absolute;left:0;color:#16a34a;font-weight:700}" +
  ".price{font-size:2.1em;font-weight:800;color:var(--ink);letter-spacing:-.02em}.card p .price{font-size:1.15em}" +
  ".cta{display:block;text-align:center;margin-top:18px;padding:13px 20px;border-radius:10px;background:linear-gradient(135deg,var(--pri),var(--pri2));color:#fff;text-decoration:none;font-weight:700}" +
  ".sub{text-align:center;margin:18px 0 0;font-size:.9em}" +
  "section.box{background:#fff;border:1px solid var(--line);border-radius:16px;padding:28px;margin-top:28px}" +
  ".vs{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin:18px 0}" +
  ".v{border:1px solid var(--line);border-radius:12px;padding:14px;font-size:.92em;color:var(--mut)}.v.on{border-color:var(--ink);box-shadow:0 0 0 3px rgba(79,70,229,.15);color:var(--ink)}" +
  ".pill{display:inline-block;font:700 .78em ui-monospace,Menlo,Consolas,monospace;border-radius:999px;padding:3px 10px;margin-bottom:8px}" +
  ".ALLOW{background:#dcfce7;color:#166534}.SILENT_VERIFY{background:#fef3c7;color:#92400e}.DECOY{background:#ede9fe;color:#5b21b6}.BLOCK{background:#fee2e2;color:#991b1b}" +
  ".now{display:flex;align-items:center;gap:10px;flex-wrap:wrap;font-weight:700;margin:0}.now .pill{margin:0;font-size:.9em}" +
  "ol{padding-left:20px;margin:14px 0 0}ol li{margin:0 0 16px}code{background:#eef1f6;border-radius:5px;padding:1px 6px;font-size:.92em}" +
  "pre{background:#0f172a;color:#e2e8f0;border-radius:10px;padding:14px;overflow-x:auto;font-size:.85em;margin:10px 0 0}" +
  "footer{color:var(--mut);font-size:.85em;text-align:center;padding:32px 0 48px}";

export function demoOrigin(url: URL, applied: Verdict): Response {
  if (url.pathname === "/api/offers") {
    return Response.json({ offers: [{ sku: "curso-pro", price: 1299 }, { sku: "mentoria", price: 4990 }] });
  }
  if (url.pathname === "/robots.txt") return new Response("User-agent: *\nAllow: /\n", { headers: { "content-type": "text/plain" } });
  const lang: Lang = url.searchParams.get("lang") === "pt" ? "pt" : "en";
  const t = TEXT[lang];
  const page = `${url.origin}/landing`;
  const items = (xs: readonly string[]) => xs.map((x) => `<li>${x}</li>`).join("");
  const verdicts = t.verdicts
    .map(([v, d]) => `<div class="v${v === applied ? " on" : ""}"><span class="pill ${v}">${v}</span><br>${d}</div>`)
    .join("");
  const html = `<!doctype html>
<html lang="${t.htmlLang}"><head><meta charset="utf-8"><title>${t.title}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>${CSS}</style></head>
<body>
<div class="hero"><div class="wrap">
<nav><span class="brand"><i></i>${t.brand}</span><a href="?lang=${lang === "en" ? "pt" : "en"}">${t.other}</a></nav>
<span class="kicker">${t.kicker}</span>
<h1>${t.h1}</h1>
<p class="lead">${t.lead}</p>
<p class="tag">${t.tag}</p>
</div></div>
<div class="wrap">
<div class="plans">
<div class="card hot"><span class="pop">${t.popular}</span><h2>${t.pro}</h2><p>${t.proDesc}</p><ul>${items(t.proItems)}</ul><div class="price">${t.proPrice}</div><p>${t.or} <span class="price">${t.proInstallment}</span></p><a class="cta" href="/checkout">${t.cta}</a></div>
<div class="card"><h2>${t.mentor}</h2><p>${t.mentorDesc}</p><ul>${items(t.mentorItems)}</ul><div class="price" data-ets-decoy>${t.mentorPrice}</div><p>&nbsp;</p><a class="cta" href="/checkout">${t.cta}</a></div>
</div>
<p class="sub"><a href="/api/offers">${t.offers}</a></p>
<section class="box"><h2>${t.aboutTitle}</h2>
<p>${t.about}</p>
<div class="vs">${verdicts}</div>
<p class="now">${t.applied}: <span class="pill ${applied}">${applied}</span></p></section>
<section class="box"><h2>${t.tryTitle}</h2>
<ol>
<li>${t.try1}</li>
<li>${t.try2}<pre>curl -si ${page} -A "python-requests/2.32" | grep -i -e x-shield-debug -e price</pre></li>
<li>${t.try3}<pre>curl -s ${page} -A "python-requests/2.32" \\
  -H "X-Eval-Context: $(node scripts/sign-eval.mjs)" | grep -o 'class="price"[^<]*<'</pre></li>
</ol></section>
<footer>${t.foot}</footer>
</div></body></html>`;
  return new Response(html, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}
