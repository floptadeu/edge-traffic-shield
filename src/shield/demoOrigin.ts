// Origem embutida para demonstração (tenant com origin = "demo").
// Simula a landing page de um cliente com preços, para mostrar DECOY e
// SILENT_VERIFY sem precisar de uma segunda origem publicada.

import type { Verdict } from "./ruleset";

export function demoOrigin(url: URL, applied: Verdict): Response {
  if (url.pathname === "/api/offers") {
    return Response.json({ offers: [{ sku: "curso-pro", price: 1299 }, { sku: "mentoria", price: 4990 }] });
  }
  if (url.pathname === "/robots.txt") return new Response("User-agent: *\nAllow: /\n", { headers: { "content-type": "text/plain" } });
  const html = `<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><title>Landing de demonstração</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px;color:#222}
.card{border:1px solid #ddd;border-radius:8px;padding:16px;margin:12px 0}.price{font-size:1.6em;font-weight:700}</style></head>
<body>
<h1>Curso Pro — turma de novembro</h1>
<p>Página servida pela origem de demonstração através do Edge Traffic Shield.</p>
<div class="card"><h2>Plano Pro</h2><p>Acesso completo por 12 meses.</p><p class="price">R$ 1.299,00</p><p>ou 12x de <span class="price">R$ 129,90</span></p></div>
<div class="card"><h2>Mentoria</h2><p>8 encontros ao vivo.</p><p class="price" data-ets-decoy>R$ 4.990,00</p></div>
<p><a href="/checkout">Quero me inscrever</a> · <a href="/api/offers">API de ofertas</a></p>
<p style="color:#888;font-size:.9em">Veredito aplicado nesta resposta: <code>${applied}</code> (veja o header X-Shield-Debug)</p>
</body></html>`;
  return new Response(html, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}
