import { describe, expect, it } from "vitest";
import { applyEvalContext } from "../src/shield/evalContext";
import { humanConn, nowSec, signEvalContext, TEST_EVAL_KEY } from "./helpers";

const payload = {
  ip: "203.0.113.7",
  asn: 16509,
  asOrganization: "Amazon",
  country: "US",
  tlsVersion: "TLSv1.2",
  tlsCipher: "AES128-GCM-SHA256",
  tlsClientHelloLength: 512,
  httpProtocol: "HTTP/1.1",
};

describe("X-Eval-Context", () => {
  it("aceita header assinado com a chave e iat dentro da janela", async () => {
    const h = await signEvalContext({ ...payload, iat: nowSec() });
    const r = await applyEvalContext(h, TEST_EVAL_KEY, humanConn());
    expect(r.status).toBe("accepted");
    if (r.status !== "accepted") return;
    expect(r.conn.ip).toBe("203.0.113.7");
    expect(r.conn.asn).toBe(16509);
    expect(r.conn.tlsClientHelloLength).toBe(512);
    expect(r.conn.httpProtocol).toBe("HTTP/1.1");
    // campo ausente no payload mantém o valor real
    expect(r.conn.colo).toBe("GRU");
  });

  it("campos ausentes usam o valor real", async () => {
    const h = await signEvalContext({ asn: 14061, iat: nowSec() });
    const r = await applyEvalContext(h, TEST_EVAL_KEY, humanConn());
    expect(r.status).toBe("accepted");
    if (r.status !== "accepted") return;
    expect(r.conn.asn).toBe(14061);
    expect(r.conn.ip).toBe("177.10.20.30");
    expect(r.conn.country).toBe("BR");
  });

  it("ignora header ausente", async () => {
    expect((await applyEvalContext(null, TEST_EVAL_KEY, humanConn())).status).toBe("absent");
  });

  it("rejeita header sem assinatura", async () => {
    const h = await signEvalContext({ ...payload, iat: nowSec() });
    const semAssinatura = h.split(".")[0]!;
    const r = await applyEvalContext(semAssinatura, TEST_EVAL_KEY, humanConn());
    expect(r.status).toBe("rejected");
  });

  it("rejeita assinatura feita com outra chave", async () => {
    const h = await signEvalContext({ ...payload, iat: nowSec() }, "chave-errada");
    const r = await applyEvalContext(h, TEST_EVAL_KEY, humanConn());
    expect(r).toEqual({ status: "rejected", reason: "signature" });
  });

  it("rejeita payload adulterado depois de assinado", async () => {
    const h = await signEvalContext({ ...payload, iat: nowSec() });
    const [, sig] = h.split(".");
    const forged = await signEvalContext({ ...payload, asn: 1, iat: nowSec() });
    const [forgedPayload] = forged.split(".");
    const r = await applyEvalContext(`${forgedPayload}.${sig}`, TEST_EVAL_KEY, humanConn());
    expect(r.status).toBe("rejected");
  });

  it("rejeita iat fora da janela de 300 s (passado e futuro)", async () => {
    const old = await signEvalContext({ ...payload, iat: nowSec() - 301 });
    expect((await applyEvalContext(old, TEST_EVAL_KEY, humanConn())).status).toBe("rejected");
    const future = await signEvalContext({ ...payload, iat: nowSec() + 301 });
    expect((await applyEvalContext(future, TEST_EVAL_KEY, humanConn())).status).toBe("rejected");
    const edge = await signEvalContext({ ...payload, iat: nowSec() - 299 });
    expect((await applyEvalContext(edge, TEST_EVAL_KEY, humanConn())).status).toBe("accepted");
  });

  it("rejeita lixo (malformado) sem lançar", async () => {
    for (const bad of ["", "abc", ".", "a.", ".b", "!!!.???", "eyJ9.AAAA", "bm90anNvbg.AAAA"]) {
      const r = await applyEvalContext(bad, TEST_EVAL_KEY, humanConn());
      expect(r.status).not.toBe("accepted");
    }
  });

  it("não aceita nada quando EVAL_KEY não está configurada", async () => {
    const h = await signEvalContext({ ...payload, iat: nowSec() });
    expect((await applyEvalContext(h, undefined, humanConn())).status).toBe("rejected");
  });
});
