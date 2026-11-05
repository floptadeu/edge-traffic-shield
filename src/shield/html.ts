// Transformações de resposta por veredito. R2: nada visível.
//   SILENT_VERIFY -> página original + <script> invisível (Turnstile invisible ou prova de JS)
//   DECOY         -> página original com dados sensíveis embaralhados + link-armadilha invisível
//   BLOCK         -> 403 curto, sem desafio, sem atraso

import type { Ruleset } from "./ruleset";

export const BEACON_PATH = "/__ets/beacon";
export const TRAP_PREFIX = "/__ets/t/";

function isHtml(res: Response): boolean {
  return (res.headers.get("content-type") ?? "").includes("text/html");
}

// Script injetado antes de </body>. Sem widget visível: o container fica display:none
// e o widget Turnstile é do tipo "Invisible" (configurado no dashboard).
export function attestationScript(challengeToken: string, siteKey: string | undefined): string {
  const c = JSON.stringify(challengeToken);
  const k = JSON.stringify(siteKey ?? "");
  return (
    `<script>(function(){var c=${c},k=${k};` +
    `function send(t){var b=JSON.stringify({c:c,t:t||""});` +
    `if(navigator.sendBeacon){navigator.sendBeacon(${JSON.stringify(BEACON_PATH)},new Blob([b],{type:"application/json"}))}` +
    `else{fetch(${JSON.stringify(BEACON_PATH)},{method:"POST",body:b,keepalive:true,headers:{"content-type":"application/json"}}).catch(function(){})}}` +
    `if(!k){send("");return}` +
    `window.__etsReady=function(){try{var d=document.createElement("div");d.style.display="none";document.body.appendChild(d);` +
    `turnstile.render(d,{sitekey:k,appearance:"interaction-only",callback:function(t){send(t)},"error-callback":function(){send("")}})}catch(e){send("")}};` +
    `var s=document.createElement("script");s.src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=__etsReady";s.async=true;s.defer=true;document.head.appendChild(s)})();</script>`
  );
}

export function injectAttestation(res: Response, challengeToken: string, siteKey: string | undefined): Response {
  if (!isHtml(res)) return res;
  const script = attestationScript(challengeToken, siteKey);
  return new HTMLRewriter()
    .on("body", {
      element(el) {
        el.append(script, { html: true });
      },
    })
    .transform(res);
}

// Embaralha dígitos mantendo o formato ("R$ 1.299,00" -> "R$ 4.871,00").
function scrambleDigits(s: string): string {
  return s.replace(/\d/g, (d) => (d === "0" ? "0" : String(1 + Math.floor(Math.random() * 9))));
}

export function decoyRewrite(res: Response, decoy: Ruleset["decoy"], trapPath: string): Response {
  if (!isHtml(res)) return res;
  let rw = new HTMLRewriter().on("body", {
    element(el) {
      // Link que nenhum humano vê nem clica; crawler que segue vira "trap".
      el.append(`<a href="${trapPath}" rel="nofollow" aria-hidden="true" tabindex="-1" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden">.</a>`, { html: true });
    },
  });
  for (const selector of decoy.selectors) {
    rw = rw.on(selector, {
      text(t) {
        if (decoy.replacement) {
          if (t.lastInTextNode) t.replace(decoy.replacement);
          else t.remove();
        } else {
          t.replace(scrambleDigits(t.text));
        }
      },
    });
  }
  const out = rw.transform(res);
  out.headers.set("x-robots-tag", "noindex, noarchive");
  return out;
}

export function blockResponse(): Response {
  return new Response("Forbidden\n", {
    status: 403,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}
