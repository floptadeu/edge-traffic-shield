// Script de carga versionado: 30k requisições (ou --rps × --duration) com o
// mix das fixtures, medindo latência (p50/p95/p99) de parede e o overhead do
// Worker (Server-Timing ets;dur) e estimando o consumo de cota do plano Free.
//
//   node scripts/load.mjs --url http://localhost:8787 --host demo.cliente.test --total 30000 --rps 500
//
// Observação: contra o deploy real isso consome cota do dia. Use local para
// calibrar e só rode remoto de propósito (ver RESULTS.md).

import { costOf, fixtureRequest, loadEvalKey, loadFixtures, parseArgs, parseDebug, percentile } from "./lib.mjs";

const args = parseArgs(process.argv.slice(2));
const baseUrl = args.url ?? "http://localhost:8787";
const host = args.host;
const evalKey = loadEvalKey(args["eval-key"]);
const total = Number(args.total ?? 30000);
const rps = Number(args.rps ?? 500);
const maxInflight = Number(args.concurrency ?? 256);
const mix = { human: 0.7, scraper: 0.17, headless: 0.1, crawler: 0.03 };

const fixtures = loadFixtures(args.fixtures ?? "fixtures");
const byLabel = Object.fromEntries(Object.keys(mix).map((l) => [l, fixtures.filter((f) => f.label === l)]));
let seed = 7;
const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
function pickFixture() {
  const r = rnd();
  let acc = 0;
  for (const [l, p] of Object.entries(mix)) {
    acc += p;
    if (r <= acc && byLabel[l].length) return byLabel[l][Math.floor(rnd() * byLabel[l].length)];
  }
  return byLabel.human[0];
}

// Assina uma vez por fixture (iat vale 300 s; a carga dura ~60 s).
const prepared = new Map();
function prep(fx) {
  let p = prepared.get(fx.id);
  if (!p) {
    p = fixtureRequest(fx, { baseUrl, host, evalKey });
    prepared.set(fx.id, p);
  }
  return p;
}

const wall = [];
const edge = [];
const verdicts = {};
const statuses = {};
const labelled = [];
let errors = 0;
let inflight = 0;
let sent = 0;
let done = 0;
const t0 = performance.now();

async function one(fx) {
  const req = prep(fx);
  const s = performance.now();
  try {
    const res = await fetch(req.url, { headers: req.headers, redirect: "manual" });
    await res.arrayBuffer();
    wall.push(performance.now() - s);
    const m = /ets;dur=(\d+)/.exec(res.headers.get("server-timing") ?? "");
    if (m) edge.push(Number(m[1]));
    const d = parseDebug(res.headers.get("x-shield-debug"));
    verdicts[d.verdict ?? "?"] = (verdicts[d.verdict ?? "?"] ?? 0) + 1;
    statuses[res.status] = (statuses[res.status] ?? 0) + 1;
    labelled.push({ expect: fx.expect, verdict: d.verdict });
  } catch {
    errors++;
  } finally {
    inflight--;
    done++;
  }
}

// Malha aberta: dispara no ritmo alvo independentemente das respostas (como o avaliador).
const intervalMs = 20;
const perTick = Math.max(1, Math.round((rps * intervalMs) / 1000));
await new Promise((resolve) => {
  const timer = setInterval(() => {
    for (let i = 0; i < perTick && sent < total; i++) {
      if (inflight >= maxInflight) break; // protege o cliente; conta como atraso de parede
      inflight++;
      sent++;
      void one(pickFixture());
    }
    if (sent >= total) {
      clearInterval(timer);
      const wait = setInterval(() => {
        if (inflight === 0) {
          clearInterval(wait);
          resolve();
        }
      }, 50);
    }
    if ((sent % 5000) === 0 && sent) process.stderr.write(`\r${sent}/${total} enviadas, ${done} concluídas, ${errors} erros   `);
  }, intervalMs);
});

const elapsed = (performance.now() - t0) / 1000;
wall.sort((a, b) => a - b);
edge.sort((a, b) => a - b);
const fmt = (arr) => `p50=${percentile(arr, 50).toFixed(1)}ms p95=${percentile(arr, 95).toFixed(1)}ms p99=${percentile(arr, 99).toFixed(1)}ms max=${(arr[arr.length - 1] ?? 0).toFixed(1)}ms`;

console.log(`\n\n== Carga: ${total} req em ${elapsed.toFixed(1)}s (${(total / elapsed).toFixed(0)} req/s efetivos, alvo ${rps}) ==`);
console.log(`erros de transporte: ${errors}`);
console.log(`status: ${JSON.stringify(statuses)}`);
console.log(`vereditos calculados: ${JSON.stringify(verdicts)}`);
console.log(`latência de parede (cliente->resposta): ${fmt(wall)}`);
console.log(`overhead do Worker (Server-Timing ets): ${fmt(edge)}  [n=${edge.length}]`);
const c = costOf(labelled.filter((l) => l.verdict));
console.log(`função de custo no mix da carga: custo=${c.cost} baseline=${c.baseline} -> ${c.points}/30`);

// --- estimativa de cota (plano Free, por rodada de `total` requisições) -------------
const shards = Number(args.shards ?? 4);
const colos = Number(args.colos ?? 1);
const durationS = elapsed;
const queueMsgs = Math.ceil(total / 100) + Math.ceil(durationS / 30) * shards * colos;
const queueOps = queueMsgs * 3;
const doPolls = Math.ceil(durationS / 2) * shards * colos;
const beacons = Math.round((verdicts.SILENT_VERIFY ?? 0) * 0.5);
const d1Rows = queueMsgs * (1 + 4 * Math.ceil(durationS / 60) + 60);
console.log(`\n== Estimativa de cota para esta rodada (${shards} shards × ${colos} colo) ==`);
console.log(`Workers requests : ${total + beacons} (+${beacons} beacons)              / 100.000 dia`);
console.log(`DO requests      : ${total + doPolls} (1/req + ${doPolls} polls de versão)   / 100.000 dia`);
console.log(`KV leituras      : < ${Math.max(10, Math.ceil(total / 500))} (memo por isolate; ~0 em regime)   / 100.000 dia`);
console.log(`KV escritas      : 0 no hot path (2 por publish de ruleset)        / 1.000 dia`);
console.log(`Queue operações  : ~${queueOps} (${queueMsgs} msgs × 3)                   / 10.000 dia`);
console.log(`D1 linhas escritas: ~${d1Rows}                                     / 100.000 dia`);
console.log(`D1 queries/invocação consumer: 2 (SELECT + batch)                  / 50`);
