// Hot path. Uma requisição do visitante passa por aqui:
//   hostname -> tenant | X-Eval-Context | sinais no Worker | R1 (crawler)
//   -> UMA chamada ao Durable Object (velocity + decisão + evento)
//   -> aplica veredito sobre a resposta da origem.
// Qualquer falha de KV/D1/DO/Queue vira ALLOW (R3) e aparece no header de debug.

import type { Env } from "../env";
import { fnv1a, timingSafeEqual } from "../lib/crypto";
import { DegradedLog, safe } from "../lib/failopen";
import type { ShardRequest, ShardResponse, SignalValue } from "../do/protocol";
import type { ShieldShard } from "../do/ShieldShard";
import { connFromRequest, type ConnInfo } from "./conn";
import { ATTEST_COOKIE, CHALLENGE_COOKIE, clearCookieHeader, cookieHeader, readAttestation, signValue, verifyValue } from "./cookies";
import { verifyCrawler } from "./crawler";
import { demoOrigin } from "./demoOrigin";
import { applyEvalContext } from "./evalContext";
import { BEACON_PATH, TRAP_PREFIX, blockResponse, decoyRewrite, injectAttestation, isHtml } from "./html";
import type { Mode, Ruleset, Verdict } from "./ruleset";
import { applyRules, evaluateSignals, formatContributions, scoreFrom, verdictFromScore, type Contribution } from "./score";
import { SIGNALS, type SignalInput } from "./signals";
import { trapSignal } from "./signals/trap";
import { velocitySignal } from "./signals/velocity";
import { STATIC_RE } from "./signals/path";
import { deriveFingerprint } from "./signals/tls";
import { parseUserAgent } from "./signals/ua";
import { loadRuleset, noteVersion, resolveTenant, type TenantHost } from "./tenant";

// Sinais calculados no Worker. velocity e trap vivem no DO.
const WORKER_SIGNALS = SIGNALS.filter((s) => s.id !== "velocity" && s.id !== "trap");

const enc = new TextEncoder();

interface Decision {
  verdict: Verdict;
  applied: Verdict;
  mode: Mode;
  score: number;
  contributions: Contribution[];
  rule?: string;
  rulesetVersion: number;
  src: "do" | "fallback";
}

export async function handleShield(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const started = Date.now();
  const log = new DegradedLog();
  const url = new URL(request.url);
  const hostname = devHostOverride(request, env) ?? url.hostname;

  const tenant = await resolveTenant(hostname, env, log);
  if (!tenant) {
    return new Response(`unknown host: ${hostname}\n`, {
      status: 404,
      headers: { "content-type": "text/plain", "x-shield-debug": `verdict=NONE; reason=unknown-host; degraded=${log}` },
    });
  }

  if (url.pathname === BEACON_PATH) return handleBeacon(request, env, tenant, log);
  if (url.pathname.startsWith(TRAP_PREFIX)) return handleTrap(request, env, ctx, tenant, url, log);

  // Assets estáticos passam direto: não pontuam, não contam velocity, não
  // gastam DO. Uma landing carrega dezenas deles por visita; contar isso
  // estouraria a janela de rajada de qualquer humano.
  if (STATIC_RE.test(url.pathname)) {
    const origin = await fetchOrigin(request, tenant, url, "ALLOW");
    const res = new Response(origin.body, origin);
    res.headers.set("x-shield-debug", "verdict=ALLOW; applied=ALLOW; reason=static-asset");
    res.headers.append("server-timing", `ets;dur=${Date.now() - started}`);
    return res;
  }

  // --- contexto da conexão (real ou do avaliador) ---
  const { conn, evalTag } = await resolveConn(request, env);

  const ua = parseUserAgent(request.headers.get("user-agent"));
  const fingerprint = deriveFingerprint(conn, ua);
  const nowSec = Math.floor(started / 1000);
  const secret = env.COOKIE_SECRET ?? "";

  const { version: workerVersion, ruleset } = await loadRuleset(tenant.tenantId, env, log);
  const attestation = secret
    ? await readAttestation(request.headers.get("cookie"), secret, fingerprint, nowSec)
    : { state: { kind: "none" as const } };

  // --- R1: crawler verificado por rede, antes de qualquer score ---
  const crawler = await verifyCrawler(ua.raw, conn.ip, conn.asn, ctx);
  let forced: ShardRequest["forced"];
  if (crawler.status === "verified") forced = { verdict: "ALLOW", reason: `verified-crawler:${crawler.family}:${crawler.via}` };
  else if (crawler.status === "error") forced = { verdict: "ALLOW", reason: `crawler-unverifiable:${crawler.family}` };

  const input: SignalInput = {
    conn,
    headers: request.headers,
    url,
    method: request.method,
    ruleset,
    fingerprint,
    attestation: attestation.state,
    crawlerSpoof: crawler.status === "spoofed",
  };

  let decision: Decision;
  try {
    decision = await decideWithDurableObject(input, tenant, workerVersion, env, ctx, log, forced, started, request);
  } catch (err) {
    // Bug inesperado no caminho de decisão: nunca derruba o site.
    log.add("worker", err instanceof Error ? err.message : String(err));
    decision = { verdict: "ALLOW", applied: "ALLOW", mode: ruleset.mode, score: 0, contributions: [], rulesetVersion: workerVersion, src: "fallback" };
  }

  const response = await applyVerdict(request, env, tenant, ruleset, decision, url, secret, fingerprint, attestation, nowSec);

  if (ruleset.debugHeader) {
    const parts = [
      `verdict=${decision.verdict}`,
      `applied=${decision.applied}`,
      `score=${decision.score}`,
      `mode=${decision.mode}`,
      `rs=v${decision.rulesetVersion}`,
      `src=${decision.src}`,
      `eval=${evalTag}`,
      `signals=${formatContributions(decision.contributions) || "-"}`,
    ];
    if (decision.rule) parts.push(`rule=${decision.rule}`);
    if (forced) parts.push(`forced=${forced.reason}`);
    if (!log.empty) parts.push(`degraded=${log}`);
    response.headers.set("x-shield-debug", parts.join("; "));
  }
  response.headers.append("server-timing", `ets;dur=${Date.now() - started}`);
  return response;
}

// Resposta tardia do DO por IP: se o DO não respondeu em 10 ms nesta
// requisição, a resposta dele (que continua chegando via waitUntil) serve
// de velocity/trap para a PRÓXIMA requisição do mesmo IP neste isolate.
interface LateHint {
  velocity: ShardResponse["velocity"];
  trapHit: boolean;
  rulesetVersion: number;
  ts: number;
}
const lateHints = new Map<string, LateHint>();
const LATE_HINT_TTL_MS = 60_000;

// Uma chamada ao DO com timeout. Sem resposta a tempo: decide aqui com a
// última velocity conhecida do IP (se houver) e sem esperar.
async function decideWithDurableObject(
  input: SignalInput,
  tenant: TenantHost,
  workerVersion: number,
  env: Env,
  ctx: ExecutionContext,
  log: DegradedLog,
  forced: ShardRequest["forced"],
  ts: number,
  request: Request,
): Promise<Decision> {
  const { conn, url, ruleset } = input;
  const signals: SignalValue[] = forced ? [] : evaluateSignals(input, WORKER_SIGNALS).map((c) => ({ id: c.id, value: c.value, reason: c.reason }));
  const ruleCtx = {
    ip: conn.ip,
    asn: conn.asn,
    country: conn.country,
    path: url.pathname,
    host: url.hostname,
    ua: input.headers.get("user-agent") ?? "",
    score: 0,
  };
  const req: ShardRequest = {
    tenantId: tenant.tenantId,
    ts,
    keys: { ip: conn.ip, asn: conn.asn, fp: input.fingerprint },
    signals,
    rule: ruleCtx,
    workerRulesetVersion: workerVersion,
    ...(forced ? { forced } : {}),
    event: { host: url.hostname, path: url.pathname, country: conn.country, colo: conn.colo },
  };

  const timeoutMs = Number(env.DO_TIMEOUT_MS ?? 5) || 5;
  const stub = shardFor(env, tenant.tenantId, conn, ruleset.velocity.shards, continentOf(request));
  const hintKey = `${tenant.tenantId}:${conn.ip}`;
  const call = stub.evaluate(req);
  // O DO conclui mesmo se não esperarmos: evento registrado, contadores atualizados,
  // e a resposta vira dica para a próxima requisição deste IP.
  ctx.waitUntil(
    call.then(
      (r) => {
        if (lateHints.size > 5000) lateHints.clear();
        lateHints.set(hintKey, { velocity: r.velocity, trapHit: r.contributions.some((c) => c.id === "trap"), rulesetVersion: r.rulesetVersion, ts: Date.now() });
        noteVersion(tenant.tenantId, r.rulesetVersion);
      },
      () => {},
    ),
  );
  const res = await safe<ShardResponse | null>("do", call, null, log, timeoutMs);

  if (res) {
    noteVersion(tenant.tenantId, res.rulesetVersion);
    return { ...res, src: "do" };
  }

  // Fallback: mesma conta, com o ruleset que o Worker tem; velocity/trap só se
  // houver dica recente do DO para este IP.
  if (forced) {
    return { verdict: forced.verdict, applied: forced.verdict, mode: ruleset.mode, score: 0, contributions: [], rule: forced.reason, rulesetVersion: workerVersion, src: "fallback" };
  }
  const contributions = signals.map((s) => {
    const weight = ruleset.weights[s.id] ?? 0;
    return { id: s.id, value: s.value, weight, points: s.value * weight, reason: s.reason };
  });
  const late = lateHints.get(hintKey);
  if (late && Date.now() - late.ts < LATE_HINT_TTL_MS) {
    const local = { ruleset, velocity: late.velocity, trapHit: late.trapHit } as SignalInput;
    for (const sig of [velocitySignal, trapSignal]) {
      const r = sig.evaluate(local);
      if (r) {
        const weight = ruleset.weights[sig.id] ?? 0;
        contributions.push({ id: sig.id, value: r.value, weight, points: r.value * weight, reason: `${r.reason}~late` });
      }
    }
  }
  const score = scoreFrom(contributions);
  let verdict = verdictFromScore(score, ruleset);
  const rule = applyRules(ruleset.rules, { ...ruleCtx, score });
  if (rule) verdict = rule.verdict;
  const applied: Verdict = ruleset.mode === "monitor" ? "ALLOW" : verdict;
  return { verdict, applied, mode: ruleset.mode, score, contributions, ...(rule ? { rule: rule.id } : {}), rulesetVersion: workerVersion, src: "fallback" };
}

// DOs não existem em toda colo: sem dica, o objeto pode nascer em outro
// continente (medi ~110 ms GRU -> América do Norte). A dica de região entra
// no nome e na criação do objeto.
const CONTINENT_HINT: Record<string, DurableObjectLocationHint> = {
  SA: "sam",
  NA: "enam",
  EU: "weur",
  AS: "apac",
  OC: "oc",
  AF: "afr",
};

export function continentOf(request: Request): string {
  const c = (request.cf as { continent?: unknown } | undefined)?.continent;
  return typeof c === "string" ? c : "XX";
}

export function shardFor(env: Env, tenantId: string, conn: ConnInfo, shards: number, continent = "XX"): DurableObjectStub<ShieldShard> {
  // Mesmo IP sempre no mesmo shard (contagem por IP exata); DO fica na região do visitante.
  const shard = fnv1a(conn.ip) % Math.max(1, shards);
  const hint = CONTINENT_HINT[continent];
  const name = `${tenantId}:${conn.colo}:${hint ?? "auto"}:${shard}`;
  const id = env.SHIELD_SHARD.idFromName(name);
  return hint ? env.SHIELD_SHARD.get(id, { locationHint: hint }) : env.SHIELD_SHARD.get(id);
}

// --- aplicação do veredito -----------------------------------------------

async function applyVerdict(
  request: Request,
  env: Env,
  tenant: TenantHost,
  ruleset: Ruleset,
  d: Decision,
  url: URL,
  secret: string,
  fingerprint: string,
  attestation: Awaited<ReturnType<typeof readAttestation>>,
  nowSec: number,
): Promise<Response> {
  if (d.applied === "BLOCK") return blockResponse();

  let res = await fetchOrigin(request, tenant, url, d.applied);
  const setCookies: string[] = [];

  if (d.applied === "SILENT_VERIFY" && secret && isHtml(res)) {
    // Só em HTML: o script é injetado junto, então o desafio sempre chega a quem
    // pode respondê-lo. Resposta JSON/asset não inicia desafio (um cliente de API
    // legítimo nunca entraria no estado "challenged" que penaliza o score).
    // Reaproveita o desafio já emitido; senão emite um novo e grava o cookie.
    let challenge: { iat: number; n: string };
    if (attestation.challenge) {
      challenge = attestation.challenge;
    } else {
      challenge = { iat: nowSec, n: crypto.randomUUID().slice(0, 8) };
      setCookies.push(cookieHeader(CHALLENGE_COOKIE, await signValue(secret, challenge), 86_400));
    }
    // O token do script NÃO é o valor do cookie: carrega js:1 e iat fresco. Quem só
    // tem o cookie (cliente HTTP que não executa a página) não consegue atestar.
    const scriptToken = await signValue(secret, { iat: nowSec, n: challenge.n, js: 1 });
    res = injectAttestation(res, scriptToken, env.TURNSTILE_SITE_KEY);
  } else if (d.applied === "DECOY") {
    const trap = secret ? `${TRAP_PREFIX}${await trapToken(secret, tenant.tenantId, Math.floor(Date.now() / TRAP_BUCKET_MS))}` : null;
    res = await decoyRewrite(res, ruleset.decoy, trap);
  }

  // Resposta mutável (headers da origem podem ser imutáveis).
  const out = new Response(res.body, res);
  for (const c of setCookies) out.headers.append("set-cookie", c);
  void fingerprint;
  return out;
}

async function fetchOrigin(request: Request, tenant: TenantHost, url: URL, applied: Verdict): Promise<Response> {
  if (tenant.origin === "demo") return demoOrigin(url, applied);
  const target = new URL(url.pathname + url.search, tenant.origin);
  const headers = new Headers(request.headers);
  headers.set("x-forwarded-host", url.hostname);
  headers.set("x-shield-verdict", applied);
  headers.delete("x-eval-context");
  try {
    return await fetch(new Request(target.toString(), { method: request.method, headers, body: request.body, redirect: "manual" }));
  } catch (err) {
    return new Response(`origin unavailable: ${err instanceof Error ? err.message : String(err)}\n`, { status: 502 });
  }
}

// Token do trap: rotaciona a cada 10 min (bucket de tempo dentro do HMAC). Um token
// estático poderia ser extraído de uma página DECOY e embutido em <img> num site de
// terceiro para envenenar o IP de visitantes inocentes; rotacionando, o token colhido
// expira em <=20 min. Sem COOKIE_SECRET não existe trap (nada de fallback adivinhável).
const TRAP_BUCKET_MS = 10 * 60_000;
const trapMemo = new Map<string, string>();
async function trapToken(secret: string, tenantId: string, bucket: number): Promise<string> {
  const k = `${tenantId}:${bucket}`;
  let t = trapMemo.get(k);
  if (!t) {
    t = (await signValue(secret, { t: tenantId, b: bucket })).split(".")[1]!.slice(0, 22);
    if (trapMemo.size > 200) trapMemo.clear();
    trapMemo.set(k, t);
  }
  return t;
}

// --- endpoints internos no host do cliente ---------------------------------

// POST /__ets/beacon  { c: <token do desafio>, t: <token Turnstile ou ""> }
async function handleBeacon(request: Request, env: Env, tenant: TenantHost, log: DegradedLog): Promise<Response> {
  const secret = env.COOKIE_SECRET;
  const noContent = () => new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
  if (request.method !== "POST" || !secret) return noContent();

  let body: { c?: unknown; t?: unknown } = {};
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return noContent();
  }
  const challenge = await verifyValue(secret, typeof body.c === "string" ? body.c : undefined);
  if (!challenge) return noContent();
  const nowSec = Math.floor(Date.now() / 1000);
  // Só o token entregue DENTRO do script (js:1) atesta — o valor do cookie não serve.
  // E tem que ser fresco (10 min): sem isso o token seria replayável para sempre.
  if (challenge.js !== 1 || typeof challenge.iat !== "number" || nowSec - challenge.iat > 600 || challenge.iat - nowSec > 60)
    return noContent();

  const { version: _v, ruleset } = await loadRuleset(tenant.tenantId, env, log);
  let kind: "ts" | "js" | null = null;
  if (env.TURNSTILE_SECRET_KEY) {
    if (typeof body.t === "string" && body.t) {
      const ok = await verifyTurnstile(env.TURNSTILE_SECRET_KEY, body.t, request.headers.get("cf-connecting-ip"));
      if (ok) kind = "ts";
    }
  } else {
    kind = "js"; // sem Turnstile configurado, vale a prova de execução de JS
  }
  if (!kind) return noContent();

  // Mesmo fingerprint que o hot path (inclusive com X-Eval-Context assinado).
  const { conn } = await resolveConn(request, env);
  const fp = deriveFingerprint(conn, parseUserAgent(request.headers.get("user-agent")));
  const att = await signValue(secret, { exp: nowSec + ruleset.attestation.ttlSec, fp, k: kind });
  const res = noContent();
  res.headers.append("set-cookie", cookieHeader(ATTEST_COOKIE, att, ruleset.attestation.ttlSec));
  res.headers.append("set-cookie", clearCookieHeader(CHALLENGE_COOKIE));
  return res;
}

async function verifyTurnstile(secret: string, token: string, ip: string | null): Promise<boolean> {
  try {
    const form = new FormData();
    form.set("secret", secret);
    form.set("response", token);
    if (ip) form.set("remoteip", ip);
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form, signal: AbortSignal.timeout(3000) });
    const j = (await r.json()) as { success?: boolean };
    return j.success === true;
  } catch {
    return false;
  }
}

// GET /__ets/t/<token>: só crawler chega aqui. Marca o IP no shard dele.
async function handleTrap(request: Request, env: Env, ctx: ExecutionContext, tenant: TenantHost, url: URL, log: DegradedLog): Promise<Response> {
  const notFound = () => new Response("Not Found\n", { status: 404, headers: { "content-type": "text/plain", "x-robots-tag": "noindex" } });
  const secret = env.COOKIE_SECRET;
  if (!secret) return notFound();
  // Browser real carregando o link embutido numa página de TERCEIRO manda
  // sec-fetch-site: cross-site; bot seguindo o link da própria página DECOY não.
  if (request.headers.get("sec-fetch-site") === "cross-site") return notFound();
  const given = url.pathname.slice(TRAP_PREFIX.length);
  const bucket = Math.floor(Date.now() / TRAP_BUCKET_MS);
  // Aceita o bucket atual e o anterior (página DECOY servida perto da virada).
  let hit = false;
  for (const b of [bucket, bucket - 1]) {
    if (timingSafeEqual(enc.encode(given), enc.encode(await trapToken(secret, tenant.tenantId, b)))) hit = true;
  }
  if (hit) {
    const { conn } = await resolveConn(request, env);
    const { ruleset } = await loadRuleset(tenant.tenantId, env, log);
    const stub = shardFor(env, tenant.tenantId, conn, ruleset.velocity.shards, continentOf(request));
    ctx.waitUntil(safe("do", stub.markTrap(conn.ip, Date.now()), undefined, log));
  }
  return notFound();
}

// request.cf real, com sobrescrita do X-Eval-Context quando (e só quando) assinado.
async function resolveConn(request: Request, env: Env): Promise<{ conn: ConnInfo; evalTag: string }> {
  const real = connFromRequest(request);
  const ev = await applyEvalContext(request.headers.get("x-eval-context"), env.EVAL_KEY, real);
  return {
    conn: ev.status === "accepted" ? ev.conn : real,
    evalTag: ev.status === "rejected" ? `rejected:${ev.reason}` : ev.status,
  };
}

// Em dev/teste: X-Shield-Host simula o hostname do cliente contra localhost.
function devHostOverride(request: Request, env: Env): string | null {
  if (env.DEV_FEATURES !== "true") return null;
  return request.headers.get("x-shield-host");
}
