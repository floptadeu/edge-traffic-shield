// Cria (ou reaproveita) o tenant de demonstração e o hostname pela API.
//
//   node scripts/bootstrap.mjs --url http://localhost:8787 --admin-key <ADMIN_API_KEY> \
//        --tenant demo --hostname demo.cliente.test --origin demo --mode enforce
//
// Imprime a API key do tenant (mostrada só na criação).

import { parseArgs } from "./lib.mjs";

const a = parseArgs(process.argv.slice(2));
const url = (a.url ?? "http://localhost:8787").replace(/\/$/, "");
const adminKey = a["admin-key"] ?? process.env.ADMIN_API_KEY;
if (!adminKey) throw new Error("--admin-key ou ADMIN_API_KEY");
const tenant = a.tenant ?? "demo";
const hostname = a.hostname ?? "demo.cliente.test";
const origin = a.origin ?? "demo";
const mode = a.mode ?? "enforce";

const api = (path, init = {}) =>
  fetch(`${url}/__ets/api${path}`, {
    ...init,
    headers: { "content-type": "application/json", authorization: `Bearer ${init.key ?? adminKey}`, ...(init.headers ?? {}) },
  });

let res = await api("/v1/tenants", { method: "POST", body: JSON.stringify({ id: tenant, name: `Tenant ${tenant}`, origin, ruleset: { mode } }) });
let apiKey;
if (res.status === 201) {
  const j = await res.json();
  apiKey = j.api_key;
  console.log(`tenant ${tenant} criado (ruleset v${j.ruleset_version}, modo ${mode})`);
  console.log(`API KEY (guarde, não é mostrada de novo): ${apiKey}`);
} else if (res.status === 409) {
  console.log(`tenant ${tenant} já existe; gerando chave nova`);
  const k = await api(`/v1/tenants/${tenant}/keys`, { method: "POST", body: "{}" });
  apiKey = (await k.json()).api_key;
  console.log(`API KEY nova: ${apiKey}`);
} else {
  throw new Error(`criar tenant: ${res.status} ${await res.text()}`);
}

res = await api(`/v1/tenants/${tenant}/domains`, { method: "POST", body: JSON.stringify({ hostname }), key: apiKey });
if (res.status === 201) {
  const j = await res.json();
  console.log(`hostname ${hostname} registrado (status ${j.domain.status}); CNAME -> ${j.domain.dns.target}`);
  if (j.domain.verification) console.log(`verificação: ${JSON.stringify(j.domain.verification)}`);
} else if (res.status === 409) console.log(`hostname ${hostname} já registrado`);
else throw new Error(`domínio: ${res.status} ${await res.text()}`);

console.log(`\nTeste: curl -si ${url}/landing -H 'X-Shield-Host: ${hostname}' | grep -i x-shield-debug`);
