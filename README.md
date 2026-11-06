# Edge Traffic Shield

SaaS multi-tenant que fica na frente do domínio do cliente (Cloudflare Workers) e
filtra scrapers e spy tools antes de chegarem à landing page, sem nenhuma fricção
visível para humanos.

```
visitante → Worker (sinais → score → ruleset → veredito) → origem do cliente
                     ALLOW · SILENT_VERIFY · DECOY · BLOCK
```

- **Stack:** TypeScript strict · Workers · D1 (fonte da verdade) · KV (config no hot path) ·
  Durable Objects (velocity + decisão + lotes) · Queues (eventos) · Cloudflare for SaaS
  (hostname do cliente) · Vitest com `@cloudflare/vitest-plugin` (o antigo
  `@cloudflare/vitest-pool-workers`, renomeado) · Wrangler 4.
- **Documentos:** [ARCHITECTURE.md](ARCHITECTURE.md) (caminho da requisição, decisões,
  conta das cotas) e [RESULTS.md](RESULTS.md) (fixtures, custo medido, latência, onde perco pontos).
- Nada de `cf.bot_management.*`: só os campos padrão de `request.cf`.

## Subir local em 10 minutos

Pré-requisitos: Node 20+ (testei com 22) e npm. Nenhuma conta Cloudflare é necessária para rodar local.

```bash
git clone <este repo> && cd edge-traffic-shield
npm install --legacy-peer-deps          # (--legacy-peer-deps contorna um bug do npm 10 com peers do vitest 5)
cp .dev.vars.example .dev.vars          # segredos de DEV (placeholders); nunca commitar .dev.vars
npm run db:migrate:local                # cria as tabelas no D1 local
npm run dev                             # wrangler dev em http://localhost:8787
```

Em outro terminal, crie o tenant de demonstração (origem embutida `demo`, modo `enforce`):

```bash
node scripts/bootstrap.mjs --url http://localhost:8787 --admin-key ets_admin_dev_troque \
  --tenant demo --hostname demo.cliente.test --origin demo --mode enforce
```

Teste os vereditos (local, `X-Shield-Host` simula o hostname do cliente; só funciona com `DEV_FEATURES=true`):

```bash
# humano: ALLOW
curl -si http://localhost:8787/landing -H 'X-Shield-Host: demo.cliente.test' \
  -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36' \
  -H 'Accept: text/html' -H 'Accept-Language: pt-BR,pt;q=0.9' -H 'Accept-Encoding: gzip' \
  -H 'Sec-CH-UA: "Chromium";v="130", "Google Chrome";v="130"' -H 'Sec-Fetch-Mode: navigate' | grep -i x-shield-debug

# scraper em nuvem (contexto assinado com a EVAL_KEY do .dev.vars): DECOY com preços embaralhados
curl -si http://localhost:8787/landing -H 'X-Shield-Host: demo.cliente.test' -A 'python-requests/2.32' \
  -H "X-Eval-Context: $(node scripts/sign-eval.mjs)" | grep -iE 'x-shield-debug|R\$'

# fail-open ao vivo: derruba KV, DO e Queue e o visitante continua sendo atendido
curl -si http://localhost:8787/landing -H 'X-Shield-Host: demo.cliente.test' -H 'X-Shield-Chaos: kv,do,queue' | grep -i x-shield-debug
```

O header `X-Shield-Debug` explica a decisão: `verdict` (calculado), `applied` (o que foi
feito; em `monitor` é sempre ALLOW), `score`, `rs=vN` (versão do ruleset), `src=do|fallback`,
`eval` (status do X-Eval-Context) e `signals=` com cada sinal, valor, peso e motivo.

## Testes, fixtures e carga

```bash
npm test                         # 97 testes dentro do runtime Workers (miniflare): sinais isolados,
                                 # R1, R2, R3 com injeção de falha, isolamento cross-tenant, API, DO, consumer
npm run typecheck
npm run fixtures:gen             # regenera fixtures/*.json (determinístico)
node scripts/eval-fixtures.mjs --url http://localhost:8787 --host demo.cliente.test   # função de custo
node scripts/load.mjs --url http://localhost:8787 --host demo.cliente.test --total 30000 --rps 500
```

## Configurar `EVAL_KEY` (e os outros segredos)

| Segredo | Para quê | Local (`.dev.vars`) | Produção |
|---|---|---|---|
| `EVAL_KEY` | verifica a assinatura do `X-Eval-Context` | placeholder | `wrangler secret put EVAL_KEY` e colar a chave enviada pelo avaliador |
| `ADMIN_API_KEY` | chave admin da API (cria tenants) | placeholder | `wrangler secret put ADMIN_API_KEY` (gere algo longo: `openssl rand -base64 32`) |
| `COOKIE_SECRET` | assina cookies de desafio/atestação e links HMAC | placeholder | `wrangler secret put COOKIE_SECRET` |
| `TURNSTILE_SITE_KEY` / `TURNSTILE_SECRET_KEY` | atestação invisível (opcional; sem eles vale a prova de JS) | vazio | `wrangler secret put ...` |
| `CF_API_TOKEN` / `CF_ZONE_ID` | criar Custom Hostnames pela API (opcional; sem eles o domínio fica em modo manual) | vazio | `wrangler secret put ...` |

Sem `EVAL_KEY` configurada o Worker **não aceita** nenhum `X-Eval-Context` (segue com `request.cf` real).
Nenhum segredo é lido de arquivo em produção; `.dev.vars` está no `.gitignore`.

## Deploy (conta Cloudflare Free)

```bash
npx wrangler login
npx wrangler kv namespace create CONFIG_KV          # copie o id para wrangler.jsonc (kv_namespaces[0].id)
npx wrangler d1 create ets-db                       # copie o database_id para wrangler.jsonc
npx wrangler queues create ets-events
npm run db:migrate:remote
npx wrangler secret put EVAL_KEY
npx wrangler secret put ADMIN_API_KEY
npx wrangler secret put COOKIE_SECRET
npx wrangler deploy                                 # sobe em https://edge-traffic-shield.<sua-conta>.workers.dev
```

Depois do deploy, crie o tenant de demonstração apontando para o workers.dev:

```bash
node scripts/bootstrap.mjs --url https://edge-traffic-shield.<sua-conta>.workers.dev \
  --admin-key '<ADMIN_API_KEY>' --tenant demo --hostname edge-traffic-shield.<sua-conta>.workers.dev --origin demo --mode enforce
```

Como o hostname registrado é o próprio `workers.dev`, a landing de demonstração fica em
`https://edge-traffic-shield.<sua-conta>.workers.dev/landing` e a API em `/__ets/api/v1/...`.

### Domínio do cliente (Cloudflare for SaaS, ponta a ponta)

1. Tenha uma zona na sua conta (o domínio da plataforma, ex. `plataforma.com`) e ative
   **SSL/TLS → Custom Hostnames** (100 hostnames inclusos no Free).
2. Crie o *fallback origin* (`shield.plataforma.com`, registro DNS proxied) e aponte uma rota do Worker
   para ele (`routes` no `wrangler.jsonc` ou `wrangler deploy --routes 'shield.plataforma.com/*'`).
   Preencha `FALLBACK_ORIGIN` em `vars`.
3. Crie um API token (permissão *SSL and Certificates: Edit* na zona) e configure
   `CF_API_TOKEN` e `CF_ZONE_ID` como secrets.
4. `POST /__ets/api/v1/tenants/{id}/domains {"hostname":"www.cliente.com"}` cria o Custom Hostname e
   devolve os registros de validação; o cliente aponta `www.cliente.com CNAME shield.plataforma.com`.
   `GET .../domains/www.cliente.com` acompanha o status até `active`.
5. Sem token (modo `manual`) o fluxo é o mesmo, só que o Custom Hostname é criado no dashboard.

### Turnstile (opcional, recomendado para a demo)

Crie um widget do tipo **Invisible** para o hostname e configure as duas chaves como secrets.
O modo `SILENT_VERIFY` injeta um script que roda o Turnstile sem nada visível e manda o token
para `/__ets/beacon`; a atestação vale para as requisições seguintes (R2).

## API de gestão (resumo)

Base: `/__ets/api/v1`. Autenticação: `Authorization: Bearer <chave>`. Chaves de tenant têm o formato
`ets_<id>_<segredo>` e só o SHA-256 do segredo fica no D1. Listas paginam por cursor (`?limit=&cursor=`).

| Método | Rota | Quem |
|---|---|---|
| POST/GET | `/tenants` | admin |
| GET/PATCH | `/tenants/{id}` | admin ou o próprio tenant |
| POST | `/tenants/{id}/keys` · DELETE `/keys/{keyId}` | tenant |
| POST/GET | `/tenants/{id}/domains` · GET/DELETE `/domains/{hostname}` | tenant |
| GET/PUT | `/tenants/{id}/ruleset` (PUT publica versão nova, propaga em ≤ 5 s) | tenant |
| GET | `/tenants/{id}/ruleset/versions` · `/versions/{v}` | tenant |
| POST | `/tenants/{id}/ruleset/rollback` `{ "version": 2 }` (sem corpo = anterior) | tenant |
| GET | `/tenants/{id}/events?verdict=&since=&limit=&cursor=` | tenant |
| GET | `/tenants/{id}/stats?from=&to=&granularity=minute\|hour` | tenant |
| POST | `/tenants/{id}/links` `{ "target": "/v1/tenants/{id}/stats", "ttl": 3600 }` → URL assinada (HMAC + TTL, só GET) | tenant |

Exemplo de ruleset (todos os campos são opcionais; o que faltar vem do default):

```json
{
  "mode": "enforce",
  "weights": { "asn": 25, "tls": 15, "headers": 20, "ua": 30, "geo": 10, "path": 10, "velocity": 25, "trap": 45, "attestation": 30 },
  "thresholds": { "silent_verify": 35, "decoy": 50, "block": 80 },
  "velocity": { "shards": 4, "windowSec": 60, "ip": 150, "asn": 2000, "fp": 1500, "burstWindowSec": 5, "ipBurst": 30 },
  "geo": { "riskCountries": [] },
  "asn": { "datacenter": [], "trusted": [] },
  "decoy": { "selectors": ["[data-ets-decoy]", ".price"], "replacement": "" },
  "rules": [ { "id": "escritorio", "if": { "field": "ip", "op": "in", "value": ["203.0.113.9"] }, "verdict": "ALLOW" } ],
  "debugHeader": true
}
```

## Mapa do código

```
src/index.ts                 entrypoint: rotas internas, API, hot path, consumer; injeção de falha (dev)
src/shield/pipeline.ts       hot path: tenant → X-Eval-Context → sinais → R1 → DO (1 chamada) → veredito
src/shield/evalContext.ts    contrato X-Eval-Context (HMAC-SHA256, tempo constante, iat ±300 s)
src/shield/signals/*.ts      um arquivo por sinal (puros, testados isoladamente)
src/shield/score.ts          soma ponderada, limiares, regras explícitas
src/shield/ruleset.ts        schema + validação + defaults do ruleset
src/shield/crawler.ts        R1: FCrDNS via DoH + ASN da Meta, com cache
src/shield/html.ts           R2: injeção invisível, decoy, bloqueio
src/shield/cookies.ts        cookies assinados de desafio/atestação
src/shield/tenant.ts         hostname → tenant (KV, fallback D1, memo) e carga do ruleset
src/shield/publish.ts        publicar/rollback: D1 → KV (chave imutável) → ponteiro no DO
src/do/ShieldShard.ts        DO por (tenant, colo, shard): velocity, decisão, lotes para a Queue
src/do/TenantConfig.ts       DO por tenant: ponteiro da versão ativa (propagação ≤ 5 s)
src/queue/consumer.ts        consumer idempotente → agregados e amostras no D1
src/api/*.ts                 API de gestão
src/lib/failopen.ts          safe(): timeout + fallback + registro de degradação (R3)
test/*.test.ts               97 testes; fixtures/ e scripts/ para custo, carga e bootstrap
```
