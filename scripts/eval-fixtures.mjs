// Roda as fixtures contra uma instância (local ou remota) e calcula a função
// de custo do enunciado: custo = 10*humanos_bloqueados + 1*bots_liberados.
//
//   node scripts/eval-fixtures.mjs --url http://localhost:8787 --host demo.cliente.test
//   node scripts/eval-fixtures.mjs --url https://demo.exemplo.com            (remoto, sem X-Shield-Host)
//
// Usa o veredito CALCULADO (verdict=) do X-Shield-Debug, então funciona em
// modo monitor também. Requer debugHeader=true no ruleset.

import { costOf, fixtureRequest, loadEvalKey, loadFixtures, parseArgs, parseDebug } from "./lib.mjs";

const args = parseArgs(process.argv.slice(2));
const baseUrl = args.url ?? "http://localhost:8787";
const host = args.host;
const evalKey = loadEvalKey(args["eval-key"]);
const concurrency = Number(args.concurrency ?? 8);
const fixtures = loadFixtures(args.fixtures ?? "fixtures");

const results = [];
let idx = 0;
async function worker() {
  while (idx < fixtures.length) {
    const fx = fixtures[idx++];
    const req = fixtureRequest(fx, { baseUrl, host, evalKey });
    try {
      const res = await fetch(req.url, { headers: req.headers, redirect: "manual" });
      await res.arrayBuffer();
      const d = parseDebug(res.headers.get("x-shield-debug"));
      results.push({ ...fx, status: res.status, verdict: d.verdict ?? "?", applied: d.applied, score: Number(d.score ?? -1), signals: d.signals, forced: d.forced, eval: d.eval, degraded: d.degraded });
    } catch (err) {
      results.push({ ...fx, status: 0, verdict: "ERROR", error: String(err) });
    }
  }
}
await Promise.all(Array.from({ length: concurrency }, worker));

// --- relatório ---------------------------------------------------------------
const labels = ["human", "crawler", "scraper", "headless"];
const verdicts = ["ALLOW", "SILENT_VERIFY", "DECOY", "BLOCK", "ERROR", "?"];
console.log("\nMatriz rótulo × veredito calculado");
console.log("label".padEnd(10) + verdicts.map((v) => v.padStart(14)).join(""));
for (const l of labels) {
  const row = results.filter((r) => r.label === l);
  if (!row.length) continue;
  console.log(l.padEnd(10) + verdicts.map((v) => String(row.filter((r) => r.verdict === v).length).padStart(14)).join(""));
}

const evalRejected = results.filter((r) => r.eval && r.eval !== "accepted");
if (evalRejected.length) console.log(`\nATENÇÃO: ${evalRejected.length} fixtures com X-Eval-Context não aceito (${evalRejected[0].eval}). A EVAL_KEY local bate com a do Worker?`);

const c = costOf(results.filter((r) => r.verdict !== "ERROR" && r.verdict !== "?"));
console.log(`\nHumanos: ${c.humans} (bloqueados: ${c.humansBlocked})  Bots: ${c.bots} (liberados: ${c.botsAllowed})`);
console.log(`custo = 10×${c.humansBlocked} + ${c.botsAllowed} = ${c.cost}   baseline (liberar tudo) = ${c.baseline}`);
console.log(`pontos estimados (bloco A) = 30 × max(0, 1 − ${c.cost}/${c.baseline}) = ${c.points} / 30`);

const crawlerFails = results.filter((r) => r.label === "crawler" && r.verdict !== "ALLOW");
if (crawlerFails.length) {
  console.log(`\nR1 EM RISCO: ${crawlerFails.length} crawler(s) não liberados:`);
  for (const r of crawlerFails) console.log(`  ${r.id} ${r.ctx.ip} -> ${r.verdict} ${r.forced ?? ""} ${r.signals ?? ""}`);
}

const humanFails = results.filter((r) => r.label === "human" && (r.verdict === "DECOY" || r.verdict === "BLOCK"));
if (humanFails.length) {
  console.log(`\nHumanos bloqueados (custam 10 cada):`);
  for (const r of humanFails) console.log(`  ${r.id} score=${r.score} ${r.note}\n      ${r.signals}`);
}

const botPass = results.filter((r) => r.expect === "DENY" && (r.verdict === "ALLOW" || r.verdict === "SILENT_VERIFY"));
console.log(`\nBots liberados (${botPass.length}), por motivo:`);
const byNote = new Map();
for (const r of botPass) {
  const k = r.note.replace(/ em .*$/, "").replace(/\d+/g, "N");
  byNote.set(k, (byNote.get(k) ?? 0) + 1);
}
for (const [k, n] of [...byNote.entries()].sort((a, b) => b[1] - a[1])) console.log(`  ${String(n).padStart(3)}  ${k}`);

if (args.out) {
  const { writeFileSync } = await import("node:fs");
  writeFileSync(args.out, JSON.stringify({ when: new Date().toISOString(), baseUrl, cost: c, results }, null, 1));
  console.log(`\nDetalhes em ${args.out}`);
}
