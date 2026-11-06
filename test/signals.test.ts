// Cada sinal testado isoladamente, com entradas controladas.
import { describe, expect, it } from "vitest";
import { DEFAULT_RULESET, type Ruleset } from "../src/shield/ruleset";
import { asnSignal } from "../src/shield/signals/asn";
import { attestationSignal } from "../src/shield/signals/attestation";
import { geoSignal } from "../src/shield/signals/geo";
import { headersSignal } from "../src/shield/signals/headers";
import { pathSignal } from "../src/shield/signals/path";
import { deriveFingerprint, tlsSignal } from "../src/shield/signals/tls";
import { trapSignal } from "../src/shield/signals/trap";
import { PASSIVE_SIGNALS, SIGNALS, type SignalInput } from "../src/shield/signals";
import { parseUserAgent, uaSignal } from "../src/shield/signals/ua";
import { velocitySignal } from "../src/shield/signals/velocity";
import { decide, scoreFrom, verdictFromScore } from "../src/shield/score";
import { CHROME_UA, chromeHeaders, humanConn } from "./helpers";

function input(over: Partial<SignalInput> = {}, ruleset: Ruleset = DEFAULT_RULESET): SignalInput {
  const headers = over.headers ?? chromeHeaders();
  return {
    conn: humanConn(),
    headers,
    ua: parseUserAgent(headers.get("user-agent")),
    url: new URL("https://cliente.exemplo/landing"),
    method: "GET",
    ruleset,
    fingerprint: "fp",
    attestation: { kind: "none" },
    crawlerSpoof: false,
    ...over,
  };
}

describe("registro de sinais", () => {
  it("tem >= 8 sinais, >= 5 passivos, todos com peso no ruleset", () => {
    expect(SIGNALS.length).toBeGreaterThanOrEqual(8);
    expect(PASSIVE_SIGNALS.length).toBeGreaterThanOrEqual(5);
    for (const s of SIGNALS) expect(typeof DEFAULT_RULESET.weights[s.id]).toBe("number");
  });
});

describe("asn", () => {
  it("humano em ISP residencial = 0", () => {
    expect(asnSignal.evaluate(input())?.value).toBe(0);
  });
  it("AWS/GCP/Hetzner = 1", () => {
    for (const asn of [16509, 396982, 24940]) {
      expect(asnSignal.evaluate(input({ conn: humanConn({ asn }) }))?.value).toBe(1);
    }
  });
  it("VPN comercial = 0.5; relay (iCloud/WARP) = 0", () => {
    expect(asnSignal.evaluate(input({ conn: humanConn({ asn: 9009 }) }))?.value).toBe(0.5);
    expect(asnSignal.evaluate(input({ conn: humanConn({ asn: 13335 }) }))?.value).toBe(0);
  });
  it("tenant pode confiar num ASN ou marcar como datacenter", () => {
    const rs: Ruleset = { ...DEFAULT_RULESET, asn: { trusted: [16509], datacenter: [28573] } };
    expect(asnSignal.evaluate(input({ conn: humanConn({ asn: 16509 }) }, rs))?.value).toBe(0);
    expect(asnSignal.evaluate(input({ conn: humanConn({ asn: 28573 }) }, rs))?.value).toBe(1);
  });
  it("nome da organização é pista fraca", () => {
    expect(asnSignal.evaluate(input({ conn: humanConn({ asn: 999999, asOrganization: "Foo Hosting Ltd" }) }))?.value).toBe(0.6);
  });
});

describe("tls (fingerprint derivado)", () => {
  it("Chrome com TLS1.3 + h2 + hello grande = coerente", () => {
    expect(tlsSignal.evaluate(input())).toEqual({ value: 0, reason: "coherent" });
  });
  it("Chrome alegado com TLS1.2 + HTTP/1.1 + hello curto = incoerente", () => {
    const r = tlsSignal.evaluate(
      input({ conn: humanConn({ tlsVersion: "TLSv1.2", httpProtocol: "HTTP/1.1", tlsClientHelloLength: 300 }) }),
    );
    expect(r!.value).toBeGreaterThanOrEqual(0.7);
    expect(r!.reason).toContain("browser-HTTP/1.1");
    expect(r!.reason).toContain("short-hello");
  });
  it("cifra CBC em navegador moderno pesa 0.8 e combina (noisy-OR) com TLS 1.2", () => {
    const r = tlsSignal.evaluate(input({ conn: humanConn({ tlsVersion: "TLSv1.2", tlsCipher: "ECDHE-RSA-AES256-SHA" }) }));
    expect(r!.reason).toContain("cbc-cipher");
    expect(r!.value).toBeGreaterThanOrEqual(0.8);
    expect(r!.value).toBeLessThan(1);
    const only = tlsSignal.evaluate(input({ conn: humanConn({ tlsCipher: "ECDHE-RSA-AES256-SHA" }) }));
    expect(only!.value).toBe(0.8);
  });
  it("ferramenta (sem navegador alegado) com TLS normal não é penalizada aqui", () => {
    const h = new Headers({ "user-agent": "python-requests/2.32" });
    expect(tlsSignal.evaluate(input({ headers: h, conn: humanConn({ httpProtocol: "HTTP/1.1" }) }))?.value).toBe(0);
  });
  it("fingerprint é estável e muda com a pilha", () => {
    const ua = parseUserAgent(CHROME_UA);
    const a = deriveFingerprint(humanConn(), ua);
    expect(a).toBe(deriveFingerprint(humanConn(), ua));
    expect(a).not.toBe(deriveFingerprint(humanConn({ httpProtocol: "HTTP/1.1" }), ua));
  });
});

describe("headers", () => {
  it("Chrome real = coerente", () => {
    expect(headersSignal.evaluate(input())?.value).toBe(0);
  });
  it("UA de Chrome sem sec-ch-ua e sem sec-fetch: duas pistas combinam (> 0.8)", () => {
    const h = new Headers({ "user-agent": CHROME_UA, accept: "text/html", "accept-language": "pt-BR,pt;q=0.9", "accept-encoding": "gzip" });
    const r = headersSignal.evaluate(input({ headers: h }));
    expect(r!.value).toBeGreaterThan(0.8);
    expect(r!.reason).toContain("chromium-without-sec-ch-ua");
    expect(r!.reason).toContain("no-sec-fetch");
  });
  it("Accept-Language de um token só (default do Playwright) = 0.5", () => {
    expect(headersSignal.evaluate(input({ headers: chromeHeaders({ "accept-language": "en-US" }) }))?.value).toBe(0.5);
    expect(headersSignal.evaluate(input({ headers: chromeHeaders({ "accept-language": "en-US,en;q=0.9" }) }))?.value).toBe(0);
  });
  it("sec-ch-ua com HeadlessChrome = 1", () => {
    const h = chromeHeaders({ "sec-ch-ua": '"HeadlessChrome";v="130", "Chromium";v="130"' });
    expect(headersSignal.evaluate(input({ headers: h }))?.value).toBe(1);
  });
  it("brand version diferente do UA = 0.9", () => {
    const h = chromeHeaders({ "sec-ch-ua": '"Chromium";v="120", "Google Chrome";v="120"' });
    expect(headersSignal.evaluate(input({ headers: h }))?.value).toBe(0.9);
  });
  it("Firefox sem client hints é normal; com client hints é suspeito", () => {
    const ff = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0";
    const ok = new Headers({ "user-agent": ff, accept: "text/html", "accept-language": "pt-BR,pt;q=0.8,en-US;q=0.5", "accept-encoding": "gzip", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" });
    expect(headersSignal.evaluate(input({ headers: ok }))?.value).toBe(0);
    ok.set("sec-ch-ua", '"Chromium";v="130"');
    expect(headersSignal.evaluate(input({ headers: ok }))?.value).toBe(0.9);
  });
  it("sem Accept-Language em navegador = 0.6", () => {
    const h = chromeHeaders();
    h.delete("accept-language");
    expect(headersSignal.evaluate(input({ headers: h }))?.value).toBe(0.6);
  });
});

describe("ua", () => {
  it("navegador = 0", () => expect(uaSignal.evaluate(input())?.value).toBe(0));
  it("ferramentas e headless = 1", () => {
    for (const ua of ["python-requests/2.32", "curl/8.4.0", "Go-http-client/1.1", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/130.0.0.0 Safari/537.36"]) {
      expect(uaSignal.evaluate(input({ headers: new Headers({ "user-agent": ua }) }))?.value).toBe(1);
    }
  });
  it("UA vazio = 0.9", () => expect(uaSignal.evaluate(input({ headers: new Headers() }))?.value).toBe(0.9));
  it("crawler alegado e não verificado = 1", () => {
    expect(uaSignal.evaluate(input({ crawlerSpoof: true }))?.value).toBe(1);
  });
  it("Chrome muito antigo = 0.4", () => {
    const h = new Headers({ "user-agent": CHROME_UA.replace("Chrome/130", "Chrome/70") });
    expect(uaSignal.evaluate(input({ headers: h }))?.value).toBe(0.4);
  });
});

describe("geo", () => {
  it("país normal com idioma compatível = 0", () => expect(geoSignal.evaluate(input())?.value).toBe(0));
  it("Tor = 0.9, desconhecido = 0.3, país de risco = 0.8", () => {
    expect(geoSignal.evaluate(input({ conn: humanConn({ country: "T1" }) }))?.value).toBe(0.9);
    expect(geoSignal.evaluate(input({ conn: humanConn({ country: "XX" }) }))?.value).toBe(0.3);
    const rs: Ruleset = { ...DEFAULT_RULESET, geo: { riskCountries: ["KP"] } };
    expect(geoSignal.evaluate(input({ conn: humanConn({ country: "KP" }) }, rs))?.value).toBe(0.8);
  });
  it("idioma incompatível é só pista fraca (0.3); inglês nunca penaliza", () => {
    expect(geoSignal.evaluate(input({ headers: chromeHeaders({ "accept-language": "zh-CN" }) }))?.value).toBe(0.3);
    expect(geoSignal.evaluate(input({ headers: chromeHeaders({ "accept-language": "en-US" }) }))?.value).toBe(0);
  });
});

describe("path", () => {
  it("landing normal = 0; asset = não se aplica", () => {
    expect(pathSignal.evaluate(input())?.value).toBe(0);
    expect(pathSignal.evaluate(input({ url: new URL("https://x/app.js") }))).toBeNull();
  });
  it("sondagem = 1; robots/sitemap = 0.6", () => {
    expect(pathSignal.evaluate(input({ url: new URL("https://x/.env") }))?.value).toBe(1);
    expect(pathSignal.evaluate(input({ url: new URL("https://x/wp-login.php") }))?.value).toBe(1);
    expect(pathSignal.evaluate(input({ url: new URL("https://x/robots.txt") }))?.value).toBe(0.6);
  });
});

describe("velocity", () => {
  it("sem contadores (DO fora) não se aplica", () => expect(velocitySignal.evaluate(input())).toBeNull());
  it("abaixo de metade do limite = 0; no limite = 1; rampa no meio", () => {
    const base = { ip: 0, ipBurst: 0, asn: 0, fp: 0 };
    const limit = DEFAULT_RULESET.velocity.ip;
    expect(velocitySignal.evaluate(input({ velocity: { ...base, ip: Math.floor(limit * 0.4) } }))?.value).toBe(0);
    expect(velocitySignal.evaluate(input({ velocity: { ...base, ip: limit } }))?.value).toBe(1);
    const mid = velocitySignal.evaluate(input({ velocity: { ...base, ip: Math.round(limit * 0.75) } }))!.value;
    expect(mid).toBeGreaterThan(0.4);
    expect(mid).toBeLessThan(0.6);
  });
  it("rajada curta por IP também conta", () => {
    const burst = DEFAULT_RULESET.velocity.ipBurst;
    const r = velocitySignal.evaluate(input({ velocity: { ip: 10, ipBurst: burst, asn: 0, fp: 0 } }));
    expect(r?.value).toBe(1);
    expect(r?.reason).toContain(`burst=${burst}/${burst}`);
  });
});

describe("trap e attestation (ativos)", () => {
  it("trap só quando o IP seguiu a armadilha", () => {
    expect(trapSignal.evaluate(input())).toBeNull();
    expect(trapSignal.evaluate(input({ trapHit: true }))?.value).toBe(1);
  });
  it("atestado = -1 (reduz score); desafio ignorado além da carência = +0.7; dentro da carência = nada", () => {
    expect(attestationSignal.evaluate(input({ attestation: { kind: "attested" } }))?.value).toBe(-1);
    expect(attestationSignal.evaluate(input({ attestation: { kind: "challenged", ageSec: 60 } }))?.value).toBe(0.7);
    expect(attestationSignal.evaluate(input({ attestation: { kind: "challenged", ageSec: 3 } }))).toBeNull();
  });
});

describe("score e veredito", () => {
  it("humano Chrome residencial = ALLOW com score 0", () => {
    const d = decide(input({ velocity: { ip: 3, ipBurst: 1, asn: 10, fp: 5 } }), "cliente.exemplo");
    expect(d.score).toBe(0);
    expect(d.verdict).toBe("ALLOW");
  });
  it("UA curto demais (ex.: 'node') = 0.8", () => {
    expect(uaSignal.evaluate(input({ headers: new Headers({ "user-agent": "node" }) }))?.value).toBe(1);
    expect(uaSignal.evaluate(input({ headers: new Headers({ "user-agent": "abc def" }) }))?.value).toBe(0.8);
  });
  it("python-requests em AWS = DECOY só com sinais passivos; com velocity vira BLOCK", () => {
    const bot = {
      conn: humanConn({ asn: 16509, asOrganization: "Amazon", tlsVersion: "TLSv1.2", httpProtocol: "HTTP/1.1", tlsClientHelloLength: 300 }),
      headers: new Headers({ "user-agent": "python-requests/2.32", accept: "*/*" }),
    };
    expect(decide(input(bot), "cliente.exemplo").verdict).toBe("DECOY");
    expect(decide(input({ ...bot, velocity: { ip: 200, ipBurst: 50, asn: 0, fp: 0 } }), "cliente.exemplo").verdict).toBe("BLOCK");
  });
  it("humano em VPN + navegador antigo (TLS1.2) + país de risco fica abaixo de DECOY", () => {
    const rs: Ruleset = { ...DEFAULT_RULESET, geo: { riskCountries: ["RU"] } };
    const d = decide(
      input({ conn: humanConn({ asn: 9009, country: "RU", tlsVersion: "TLSv1.2" }), headers: chromeHeaders({ "accept-language": "ru" }) }, rs),
      "cliente.exemplo",
    );
    expect(d.verdict).not.toBe("DECOY");
    expect(d.verdict).not.toBe("BLOCK");
  });
  it("pesos por tenant mudam o resultado", () => {
    const rs: Ruleset = { ...DEFAULT_RULESET, weights: { ...DEFAULT_RULESET.weights, asn: 90 } };
    const d = decide(input({ conn: humanConn({ asn: 16509 }) }, rs), "cliente.exemplo");
    expect(d.score).toBe(90);
    expect(d.verdict).toBe("BLOCK");
  });
  it("atestação derruba o score (clamp em 0)", () => {
    expect(scoreFrom([{ id: "asn", value: 1, weight: 20, points: 20, reason: "" }, { id: "attestation", value: -1, weight: 30, points: -30, reason: "" }])).toBe(0);
  });
  it("limiares configuráveis", () => {
    const rs: Ruleset = { ...DEFAULT_RULESET, thresholds: { silent_verify: 10, decoy: 20, block: 30 } };
    expect(verdictFromScore(9, rs)).toBe("ALLOW");
    expect(verdictFromScore(10, rs)).toBe("SILENT_VERIFY");
    expect(verdictFromScore(25, rs)).toBe("DECOY");
    expect(verdictFromScore(30, rs)).toBe("BLOCK");
  });
  it("regra explícita sobrescreve o score (allowlist de IP e prefixo de path)", () => {
    const rs: Ruleset = {
      ...DEFAULT_RULESET,
      rules: [
        { id: "office", if: { field: "ip", op: "in", value: ["203.0.113.9"] }, verdict: "ALLOW" },
        { id: "api", if: { field: "path", op: "prefix", value: "/api/" }, verdict: "ALLOW" },
        { id: "bad-asn", if: { field: "asn", op: "eq", value: 4134 }, verdict: "BLOCK" },
      ],
    };
    const bot = { conn: humanConn({ asn: 16509, ip: "203.0.113.9" }), headers: new Headers({ "user-agent": "curl/8" }) };
    expect(decide(input(bot, rs), "h").rule).toBe("office");
    expect(decide(input(bot, rs), "h").verdict).toBe("ALLOW");
    expect(decide(input({ url: new URL("https://x/api/v1/x"), conn: humanConn({ asn: 16509 }) }, rs), "h").verdict).toBe("ALLOW");
    expect(decide(input({ conn: humanConn({ asn: 4134 }) }, rs), "h").verdict).toBe("BLOCK");
  });
});
