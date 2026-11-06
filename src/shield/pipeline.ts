// Hot path. Uma requisição do visitante passa por aqui:
//   hostname -> tenant | X-Eval-Context | sinais no Worker | R1 (crawler)
//   -> UMA chamada ao Durable Object (velocity + decisão + evento)
//   -> aplica veredito sobre a resposta da origem.
// Qualquer falha de KV/D1/DO/Queue vira ALLOW (R3) e aparece no header de debug.

import type { Env } from "../env";
import { fnv1a } from "../lib/crypto";
import { DegradedLog, safe } from "../lib/failopen";
import type { ShardRequest, ShardResponse, SignalValue } from "../do/protocol";
import type { ShieldShard } from "../do/ShieldShard";
import { connFromRequest, type ConnInfo } from "./conn";
import { ATTEST_COOKIE, CHALLENGE_COOKIE, clearCookieHeader, cookieHeader, readAttestation, signValue, verifyValue } from "./cookies";
import { verifyCrawler } from "./crawler";
import { demoOrigin } from "./demoOrigin";
import { applyEvalContext } from "./evalContext";
import { BEACON_PATH, TRAP_PREFIX, blockResponse, decoyRewrite, injectAttestation } from "./html";
import type { Mode, Ruleset, Verdict } from "./ruleset";
import { applyRules, evaluateSignals, formatContributions, scoreFrom, verdictFromScore, type Contribution } from "./score";
import { SIGNALS, type SignalInput } from "./signals";
import { deriveFingerprint } from "./signals/tls";
import { parseUserAgent } from "./signals/ua";
import { loadRuleset, noteVersion, resolveTenant, type TenantHost } from "./tenant";

// Sinais calculados no Worker. velocity e trap vivem no DO.
const WORKER_SIGNALS = SIGNALS.filter((s) => s.id !== "velocity" && s.id !== "trap");

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
    decision = await decideWithDurableObject(input, tenant, workerVersion, env, log, forced, started);
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

// Uma chamada ao DO com timeout. Sem resposta a tempo: decide aqui sem velocity/trap.
async function decideWithDurableObject(
  input: SignalInput,
  tenant: TenantHost,
  workerVersion: number,
  env: Env,
  log: DegradedLog,
  forced: ShardRequest["forced"],
  ts: number,
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

  const timeoutMs = Number(env.DO_TIMEOUT_MS ?? 10) || 10;
  const stub = shardFor(env, tenant.tenantId, conn, ruleset.velocity.shards);
  const res = await safe<ShardResponse | null>("do", stub.evaluate(req), null, log, timeoutMs);

  if (res) {
    noteVersion(tenant.tenantId, res.rulesetVersion);
    return { ...res, src: "do" };
  }

  // Fallback: mesma conta, com o ruleset que o Worker tem, sem velocity/trap.
  if (forced) {
    return { verdict: forced.verdict, applied: forced.verdict, mode: ruleset.mode, score: 0, contributions: [], rule: forced.reason, rulesetVersion: workerVersion, src: "fallback" };
  }
  const contributions = signals.map((s) => {
    const weight = ruleset.weights[s.id] ?? 0;
    return { id: s.id, value: s.value, weight, points: s.value * weight, reason: s.reason };
  });
  const score = scoreFrom(contributions);
  let verdict = verdictFromScore(score, ruleset);
  const rule = applyRules(ruleset.rules, { ...ruleCtx, score });
  if (rule) verdict = rule.verdict;
  const applied: Verdict = ruleset.mode === "monitor" ? "ALLOW" : verdict;
  return { verdict, applied, mode: ruleset.mode, score, contributions, ...(rule ? { rule: rule.id } : {}), rulesetVersion: workerVersion, src: "fallback" };
}

export function shardFor(env: Env, tenantId: string, conn: ConnInfo, shards: number): DurableObjectStub<ShieldShard> {
  // Mesmo IP sempre no mesmo shard (contagem por IP exata); DO fica na colo do visitante.
  const shard = fnv1a(conn.ip) % Math.max(1, shards);
  const name = `${tenantId}:${conn.colo}:${shard}`;
  return env.SHIELD_SHARD.get(env.SHIELD_SHARD.idFromName(name));
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

  let res = await fetchOrigin(request, tenant, url, d);
  const setCookies: string[] = [];

  if (d.applied === "SILENT_VERIFY" && secret) {
    // Reaproveita o desafio já emitido; senão emite um novo e grava o cookie.
    let token: string;
    if (attestation.challenge) {
      token = await signValue(secret, attestation.challenge);
    } else {
      token = await signValue(secret, { iat: nowSec, n: crypto.randomUUID().slice(0, 8) });
      setCookies.push(cookieHeader(CHALLENGE_COOKIE, token, 86_400));
    }
    res = injectAttestation(res, token, env.TURNSTILE_SITE_KEY);
  } else if (d.applied === "DECOY") {
    res = decoyRewrite(res, ruleset.decoy, `${TRAP_PREFIX}${await trapToken(secret, tenant.tenantId)}`);
  }

  // Resposta mutável (headers da origem podem ser imutáveis).
  const out = new Response(res.body, res);
  for (const c of setCookies) out.headers.append("set-cookie", c);
  void fingerprint;
  return out;
}

async function fetchOrigin(request: Request, tenant: TenantHost, url: URL, d: Decision): Promise<Response> {
  if (tenant.origin === "demo") return demoOrigin(url, d.applied);
  const target = new URL(url.pathname + url.search, tenant.origin);
  const headers = new Headers(request.headers);
  headers.set("x-forwarded-host", url.hostname);
  headers.set("x-shield-verdict", d.applied);
  headers.delete("x-eval-context");
  try {
    return await fetch(new Request(target.toString(), { method: request.method, headers, body: request.body, redirect: "manual" }));
  } catch (err) {
    return new Response(`origin unavailable: ${err instanceof Error ? err.message : String(err)}\n`, { status: 502 });
  }
}

const trapMemo = new Map<string, string>();
async function trapToken(secret: string, tenantId: string): Promise<string> {
  let t = trapMemo.get(tenantId);
  if (!t) {
    t = (await signValue(secret || "no-secret", { t: tenantId })).split(".")[1]!.slice(0, 22);
    trapMemo.set(tenantId, t);
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
  const nowSec = Math.floor(Date.now() / 1000);
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
  const expected = await trapToken(env.COOKIE_SECRET ?? "", tenant.tenantId);
  const given = url.pathname.slice(TRAP_PREFIX.length);
  if (given === expected) {
    const { conn } = await resolveConn(request, env);
    const { ruleset } = await loadRuleset(tenant.tenantId, env, log);
    const stub = shardFor(env, tenant.tenantId, conn, ruleset.velocity.shards);
    ctx.waitUntil(safe("do", stub.markTrap(conn.ip, Date.now()), undefined, log));
  }
  return new Response("Not Found\n", { status: 404, headers: { "content-type": "text/plain", "x-robots-tag": "noindex" } });
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
