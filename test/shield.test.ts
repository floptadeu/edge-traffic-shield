// Hot path de ponta a ponta: vereditos, modo monitor, debug header,
// X-Eval-Context integrado, SILENT_VERIFY sem fricção (R2) e atestação assíncrona.
import { describe, expect, it } from "vitest";
import { CONN, createTenant, debugOf, evalHeader, visit } from "./e2e";
import { CHROME_UA, chromeHeaders, nowSec, signEvalContext } from "./helpers";

const TOOL_HEADERS = { "user-agent": "python-requests/2.32.3", accept: "*/*", "accept-encoding": "gzip, deflate" };

describe("hot path", () => {
  it("humano em navegador real recebe ALLOW com header de debug explicando", async () => {
    const t = await createTenant({ ruleset: { mode: "enforce" } });
    const res = await visit(t.hostname, "/landing", chromeHeaders({ "x-eval-context": await evalHeader(CONN.humanBR) }));
    expect(res.status).toBe(200);
    const d = debugOf(res);
    expect(d.verdict).toBe("ALLOW");
    expect(d.applied).toBe("ALLOW");
    expect(d.score).toBe("0");
    expect(d.eval).toBe("accepted");
    expect(d.src).toBe("do");
    expect(d.rs).toBe("v1");
    expect(res.headers.get("server-timing")).toMatch(/ets;dur=\d+/);
    expect(await res.text()).toContain("R$ 1.299,00");
  });

  it("modo monitor: calcula o veredito mas aplica ALLOW", async () => {
    const t = await createTenant({ ruleset: { mode: "monitor" } });
    const res = await visit(t.hostname, "/landing", { ...TOOL_HEADERS, "x-eval-context": await evalHeader(CONN.awsTool) });
    expect(res.status).toBe(200);
    const d = debugOf(res);
    expect(d.verdict).toBe("DECOY");
    expect(d.applied).toBe("ALLOW");
    expect(d.mode).toBe("monitor");
    expect(d.signals).toContain("asn:1*25");
    expect(d.signals).toContain("ua:1*30");
    expect(await res.text()).toContain("R$ 1.299,00"); // conteúdo intacto
  });

  it("DECOY em enforce: 200 com preços embaralhados e link-armadilha invisível", async () => {
    const t = await createTenant({ ruleset: { mode: "enforce" } });
    const res = await visit(t.hostname, "/landing", { ...TOOL_HEADERS, "x-eval-context": await evalHeader(CONN.awsTool) });
    expect(res.status).toBe(200);
    expect(debugOf(res).applied).toBe("DECOY");
    const html = await res.text();
    expect(html).not.toContain("R$ 1.299,00");
    expect(html).toMatch(/R\$ \d\.\d{3},00/); // mesmo formato, outros dígitos
    expect(html).toContain('/__ets/t/');
    expect(html).toContain("left:-9999px");
    expect(res.headers.get("x-robots-tag")).toContain("noindex");
  });

  it("seguir o link-armadilha marca o IP e as próximas viram BLOCK", async () => {
    const t = await createTenant({ ruleset: { mode: "enforce" } });
    const ctx = await evalHeader(CONN.awsTool, { ip: "3.120.10.77" });
    const first = await visit(t.hostname, "/landing", { ...TOOL_HEADERS, "x-eval-context": ctx });
    const trap = /href="(\/__ets\/t\/[^"]+)"/.exec(await first.text())?.[1];
    expect(trap).toBeDefined();
    const hit = await visit(t.hostname, trap!, { ...TOOL_HEADERS, "x-eval-context": ctx });
    expect(hit.status).toBe(404);
    await new Promise((r) => setTimeout(r, 50));
    const after = await visit(t.hostname, "/landing", { ...TOOL_HEADERS, "x-eval-context": ctx });
    expect(after.status).toBe(403);
    expect(debugOf(after).signals).toContain("trap:1*45");
  });

  it("DECOY não vaza preço real em JSON: /api/offers também sai embaralhado", async () => {
    const t = await createTenant({ ruleset: { mode: "enforce" } });
    const res = await visit(t.hostname, "/api/offers", { ...TOOL_HEADERS, "x-eval-context": await evalHeader(CONN.awsTool) });
    expect(debugOf(res).applied).toBe("DECOY");
    const data = (await res.json()) as { offers: Array<{ price: number }> };
    expect(Array.isArray(data.offers)).toBe(true); // JSON continua válido
    expect(data.offers.map((o) => o.price)).not.toEqual([1299, 4990]);
  });

  it("trap: cross-site não marca (humano com o link embutido em site de terceiro) e token de bucket velho não marca", async () => {
    const t = await createTenant({ ruleset: { mode: "enforce" } });
    const ctx = await evalHeader(CONN.awsTool, { ip: "3.120.10.78" });
    const first = await visit(t.hostname, "/landing", { ...TOOL_HEADERS, "x-eval-context": ctx });
    const trap = /href="(\/__ets\/t\/[^"]+)"/.exec(await first.text())?.[1];
    expect(trap).toBeDefined();
    // browser de visitante inocente carregando <img src=trap> embutido por terceiro
    await visit(t.hostname, trap!, { ...TOOL_HEADERS, "x-eval-context": ctx, "sec-fetch-site": "cross-site" });
    // token colhido há 20-30 min (2 buckets atrás): expirou
    const oldBucket = Math.floor(Date.now() / 600_000) - 2;
    const oldToken = (await signEvalContext({ t: t.id, b: oldBucket }, "test-cookie-secret")).split(".")[1]!.slice(0, 22);
    await visit(t.hostname, `/__ets/t/${oldToken}`, { ...TOOL_HEADERS, "x-eval-context": ctx });
    await new Promise((r) => setTimeout(r, 50));
    const after = await visit(t.hostname, "/landing", { ...TOOL_HEADERS, "x-eval-context": ctx });
    expect(debugOf(after).signals ?? "").not.toContain("trap:");
  });

  it("rajada do mesmo IP sobe a velocity (janela deslizante no DO): sozinha não bloqueia humano, mas fecha a conta de um bot", async () => {
    const vel = { shards: 1, windowSec: 60, ip: 20, asn: 10000, fp: 10000, burstWindowSec: 5, ipBurst: 10 };
    const t = await createTenant({ ruleset: { mode: "enforce", velocity: vel } });
    // Navegador real residencial em rajada (NAT compartilhado): velocity sozinha = 30 => ALLOW
    const human = await evalHeader(CONN.humanBR, { ip: "177.10.20.88" });
    let last: Response | undefined;
    for (let i = 0; i < 14; i++) last = await visit(t.hostname, "/landing", chromeHeaders({ "x-eval-context": human }));
    expect(debugOf(last!).signals).toContain("velocity:1*25");
    expect(debugOf(last!).applied).toBe("ALLOW");
    expect(last!.status).toBe(200);
    // Assets não contam velocity nem passam pelo DO
    const asset = await visit(t.hostname, "/app.css", chromeHeaders({ "x-eval-context": human }));
    expect(asset.headers.get("x-shield-debug")).toContain("static-asset");
    // Ferramenta em rajada: 25 + 10 + 30 + 30 = 95 => BLOCK
    const bot = await evalHeader(CONN.aws, { ip: "3.120.10.89" });
    for (let i = 0; i < 14; i++) last = await visit(t.hostname, "/landing", { ...TOOL_HEADERS, "x-eval-context": bot });
    expect(debugOf(last!).applied).toBe("BLOCK");
    expect(last!.status).toBe(403);
  });

  it("X-Eval-Context sem assinatura válida é ignorado e a conexão real prevalece", async () => {
    const t = await createTenant({ ruleset: { mode: "enforce" } });
    const forged = (await evalHeader(CONN.awsTool)).split(".")[0] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const res = await visit(t.hostname, "/landing", chromeHeaders({ "x-eval-context": forged }));
    expect(res.status).toBe(200);
    const d = debugOf(res);
    expect(d.eval).toBe("rejected:signature");
    expect(d.signals).not.toContain("asn:1");
  });

  it("R2: SILENT_VERIFY devolve a página original + script invisível e a atestação vale para a próxima", async () => {
    // AWS (25) + Chrome em HTTP/1.1 (10.5) = 35.5 => SILENT_VERIFY
    const t = await createTenant({ ruleset: { mode: "enforce" } });
    const ctx = await evalHeader(CONN.aws, { ip: "3.120.10.99", httpProtocol: "HTTP/1.1" });
    const res = await visit(t.hostname, "/landing", chromeHeaders({ "x-eval-context": ctx }));
    expect(res.status).toBe(200);
    expect(debugOf(res).applied).toBe("SILENT_VERIFY");
    const html = await res.text();
    // Conteúdo intacto, nada visível, nenhum desafio interativo.
    expect(html).toContain("R$ 1.299,00");
    expect(html).toContain("/__ets/beacon");
    expect(html).toContain('display="none"'.replace('="', "=\"") === 'display="none"' ? "display=\"none\"" : "display=\"none\"");
    expect(html).not.toMatch(/captcha|checkbox|verifique|aguarde/i);
    const setCookie = res.headers.get("set-cookie") ?? "";
    expect(setCookie).toContain("__ets_c=");
    const challenge = /var c="([^"]+)"/.exec(html)?.[1];
    expect(challenge).toBeDefined();

    // Beacon assíncrono (sem Turnstile configurado = prova de JS)
    const beacon = await visit(t.hostname, "/__ets/beacon", chromeHeaders({ "x-eval-context": ctx, "content-type": "application/json" }), {
      method: "POST",
      body: JSON.stringify({ c: challenge, t: "" }),
    });
    expect(beacon.status).toBe(204);
    const att = /__ets_att=([^;]+)/.exec(beacon.headers.get("set-cookie") ?? "")?.[1];
    expect(att).toBeDefined();

    // Próxima requisição: atestado => score cai => ALLOW
    const next = await visit(t.hostname, "/landing", chromeHeaders({ "x-eval-context": ctx, cookie: `__ets_att=${att}` }));
    const d = debugOf(next);
    expect(d.signals).toContain("attestation:-1*30");
    expect(d.applied).toBe("ALLOW");

    // Cookie de atestação não serve para outra pilha (python com o mesmo IP)
    const replay = await visit(t.hostname, "/landing", { ...TOOL_HEADERS, "x-eval-context": ctx, cookie: `__ets_att=${att}` });
    expect(debugOf(replay).signals).not.toContain("attestation:-1");
  });

  it("desafio ignorado além da carência soma ao score", async () => {
    const t = await createTenant({ ruleset: { mode: "enforce", attestation: { ttlSec: 3600, challengeGraceSec: 1 } } });
    const ctx = await evalHeader(CONN.aws, { ip: "3.120.10.100", httpProtocol: "HTTP/1.1" });
    const res = await visit(t.hostname, "/landing", chromeHeaders({ "x-eval-context": ctx }));
    const c = /__ets_c=([^;]+)/.exec(res.headers.get("set-cookie") ?? "")?.[1];
    await new Promise((r) => setTimeout(r, 2100));
    const later = await visit(t.hostname, "/landing", chromeHeaders({ "x-eval-context": ctx, cookie: `__ets_c=${c}` }));
    expect(debugOf(later).signals).toContain("attestation:0.7*30");
  }, 10_000);

  it("beacon rejeita o valor do cookie e token js com iat velho (só atesta o token fresco do script)", async () => {
    const t = await createTenant({ ruleset: { mode: "enforce" } });
    const ctx = await evalHeader(CONN.aws, { ip: "3.120.10.101", httpProtocol: "HTTP/1.1" });
    const res = await visit(t.hostname, "/landing", chromeHeaders({ "x-eval-context": ctx }));
    const cookieToken = /__ets_c=([^;]+)/.exec(res.headers.get("set-cookie") ?? "")?.[1];
    expect(cookieToken).toBeDefined();
    const beaconWith = (c: string) =>
      visit(t.hostname, "/__ets/beacon", chromeHeaders({ "x-eval-context": ctx, "content-type": "application/json" }), {
        method: "POST",
        body: JSON.stringify({ c, t: "" }),
      });
    // curl que só tem o cookie (nunca executou a página): sem atestação
    const b1 = await beaconWith(cookieToken!);
    expect(b1.status).toBe(204);
    expect(b1.headers.get("set-cookie") ?? "").not.toContain("__ets_att=");
    // token js assinado mas velho (1h): replay rejeitado
    const stale = await signEvalContext({ iat: nowSec() - 3600, n: "abcd1234", js: 1 }, "test-cookie-secret");
    const b2 = await beaconWith(stale);
    expect(b2.headers.get("set-cookie") ?? "").not.toContain("__ets_att=");
  });

  it("R2/score: SILENT_VERIFY em resposta não-HTML não seta desafio (cliente de API não acumula penalidade)", async () => {
    const t = await createTenant({ ruleset: { mode: "enforce", attestation: { ttlSec: 3600, challengeGraceSec: 1 } } });
    const ctx = await evalHeader(CONN.aws, { ip: "3.120.10.102", httpProtocol: "HTTP/1.1" });
    const res = await visit(t.hostname, "/api/offers", chromeHeaders({ "x-eval-context": ctx }));
    expect(debugOf(res).applied).toBe("SILENT_VERIFY");
    expect(res.headers.get("set-cookie") ?? "").not.toContain("__ets_c=");
    // sem desafio emitido, não existe "challenge-ignored" depois da carência
    await new Promise((r) => setTimeout(r, 1100));
    const later = await visit(t.hostname, "/api/offers", chromeHeaders({ "x-eval-context": ctx }));
    expect(debugOf(later).signals ?? "").not.toContain("attestation:0.7");
  }, 10_000);

  it("hostname desconhecido não é proxiado", async () => {
    const res = await visit("ninguem.cliente.test");
    expect(res.status).toBe(404);
  });

  it("header de debug pode ser desligado pelo ruleset", async () => {
    const t = await createTenant({ ruleset: { debugHeader: false } });
    const res = await visit(t.hostname, "/landing", chromeHeaders({ "user-agent": CHROME_UA }));
    expect(res.headers.get("x-shield-debug")).toBeNull();
  });
});
