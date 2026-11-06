// Utilidades compartilhadas pelos scripts (Node >= 20, sem dependências).
import { createHmac } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";

export function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) out[key] = true;
    else {
      out[key] = next;
      i++;
    }
  }
  return out;
}

// EVAL_KEY: variável de ambiente ou .dev.vars (nunca commitado).
export function loadEvalKey(explicit) {
  if (explicit) return explicit;
  if (process.env.EVAL_KEY) return process.env.EVAL_KEY;
  const p = path.resolve(process.cwd(), ".dev.vars");
  if (existsSync(p)) {
    const m = /^EVAL_KEY=(.*)$/m.exec(readFileSync(p, "utf8"));
    if (m) return m[1].trim().replace(/^["']|["']$/g, "");
  }
  throw new Error("EVAL_KEY não encontrada (use --eval-key, EVAL_KEY=... ou .dev.vars)");
}

export function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

export function signEvalContext(payload, key) {
  const body = Buffer.from(JSON.stringify({ ...payload, iat: Math.floor(Date.now() / 1000) }));
  const sig = createHmac("sha256", key).update(body).digest();
  return `${b64url(body)}.${b64url(sig)}`;
}

export function parseDebug(header) {
  const out = {};
  for (const part of (header ?? "").split("; ")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i)] = part.slice(i + 1);
  }
  return out;
}

export function percentile(sorted, p) {
  if (!sorted.length) return 0;
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, idx)];
}

export function loadFixtures(dir = "fixtures") {
  const files = ["human.json", "scraper.json", "headless.json", "crawler.json"];
  const all = [];
  for (const f of files) {
    const p = path.join(dir, f);
    if (!existsSync(p)) continue;
    all.push(...JSON.parse(readFileSync(p, "utf8")));
  }
  return all;
}

// Monta a requisição de uma fixture contra a plataforma.
export function fixtureRequest(fx, { baseUrl, host, evalKey }) {
  const headers = { ...fx.headers };
  // Node/undici manda "user-agent: node" quando o header falta; UA vazio de verdade exige o valor "".
  if (headers["user-agent"] === undefined) headers["user-agent"] = "";
  if (host) headers["x-shield-host"] = host; // só funciona com DEV_FEATURES=true
  headers["x-eval-context"] = signEvalContext(fx.ctx, evalKey);
  return { url: `${baseUrl.replace(/\/$/, "")}${fx.path ?? "/landing"}`, headers };
}

// Função de custo do enunciado. "Bloqueado" = DECOY ou BLOCK (decisão conservadora:
// humano vendo preço falso está, na prática, bloqueado).
export function costOf(results) {
  let humansBlocked = 0;
  let botsAllowed = 0;
  let humans = 0;
  let bots = 0;
  for (const r of results) {
    const denied = r.verdict === "DECOY" || r.verdict === "BLOCK";
    if (r.expect === "ALLOW") {
      humans++;
      if (denied) humansBlocked++;
    } else {
      bots++;
      if (!denied) botsAllowed++;
    }
  }
  const cost = 10 * humansBlocked + botsAllowed;
  const baseline = bots; // liberar tudo: todos os bots passam, nenhum humano bloqueado
  const points = 30 * Math.max(0, 1 - (baseline ? cost / baseline : 0));
  return { humans, bots, humansBlocked, botsAllowed, cost, baseline, points: Number(points.toFixed(1)) };
}
