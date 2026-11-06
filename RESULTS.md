# Resultados

Medições feitas em 05/11/2026. Comandos e saídas brutas em `results/`.

## Como montei as fixtures

Não existe conjunto de calibração, então gerei o meu (`scripts/gen-fixtures.mjs`, seed fixa,
`npm run fixtures:gen` reproduz byte a byte). Cada fixture tem o contexto de conexão (vai assinado
no `X-Eval-Context`), os headers e o rótulo:

| Arquivo | Qtde | Como foi montado |
|---|---:|---|
| `fixtures/human.json` | 160 | 7 perfis reais de navegador (Chrome Win/Mac/Android, Edge, Firefox, Safari Mac/iPhone) com os headers que cada um manda numa navegação de documento, em 10 ISPs residenciais (BR, US, PT, MX, AR, DE). 30 % são casos difíceis de propósito: VPN comercial (M247/Datacamp), Chrome 109 no Windows 7 (TLS 1.2), proxy corporativo (HTTP/1.1), iCloud Private Relay/WARP, `Accept-Language` de outro país. |
| `fixtures/scraper.json` | 120 | 45 % ferramenta crua em nuvem (`python-requests`, `httpx`, `curl`, `Go-http-client`, `Scrapy`, `axios`, `Java`, UA vazio); 25 % UA de Chrome colado num cliente HTTP (sem Client Hints, HTTP/1.1, ClientHello curto); 15 % headers completos copiados do DevTools com pilha TLS de Python/Go; 15 % `curl-impersonate` (TLS idêntico ao Chrome), metade em proxy residencial. |
| `fixtures/headless.json` | 80 | 40 % Playwright headless shell (`HeadlessChrome`, hints com brand headless, `Accept-Language: en-US`); 25 % UA sobrescrito mas `sec-ch-ua-platform` Linux com UA Windows; 20 % stealth consistente em nuvem; 15 % stealth + proxy residencial (indistinguível por sinal passivo). |
| `fixtures/crawler.json` | 19 | Googlebot (desktop/smartphone), AdsBot, bingbot, facebookexternalhit, Bytespider, com IPs reais que têm rDNS forward-confirmed (a avaliação consulta DoH de verdade) ou AS32934 (Meta). |

Função de custo do enunciado, com a interpretação conservadora de que **DECOY também é
"humano bloqueado"** (um comprador vendo preço falso está, na prática, bloqueado) e
`SILENT_VERIFY` é "liberado" (o humano recebe a página real).

## Custo medido nas fixtures (`node scripts/eval-fixtures.mjs`)

Local (`wrangler dev`) e no deploy deram o mesmo resultado — é determinístico por construção.

```
label              ALLOW SILENT_VERIFY         DECOY         BLOCK
human                160             0             0             0
crawler               19             0             0             0
scraper               18            22            80             0
headless              26            13            41             0

Humanos: 179 (bloqueados: 0)  Bots: 200 (liberados: 79)
custo = 10×0 + 79 = 79   baseline (liberar tudo) = 200
pontos estimados (bloco A) = 30 × (1 − 79/200) = 18,1 / 30
```

Quem passa (79): `curl-impersonate` e Playwright stealth em proxy residencial (0 sinais passivos),
stealth em nuvem (só o ASN = 25, abaixo de DECOY), headers copiados com TLS de `httpx`
(ASN 25 + ClientHello curto 13,5 = 38,5) e headless com plataforma incoerente (25 + 18 = 43).
Esses dois últimos grupos ficam entre 35 e 50 de propósito: a linha de DECOY (50) exige ≥ 2
indicadores fortes independentes, porque o humano mais estranho que modelei (VPN + Chrome 109 +
proxy HTTP/1.1) chega a ~42.

Sensibilidade medida: com `thresholds.decoy = 40` o custo cai para 53 (**22,1/30**) e **ainda zero
humanos bloqueados nas minhas fixtures**, mas a margem para humanos reais fora das fixtures fica
de 2 pontos. Deixei 50 como default e documentei o botão: é um `PUT /ruleset`, sem deploy.
No dia da avaliação prefiro perder 4 pontos de bots do que arriscar 10 por humano.

## Latência

| Onde | Overhead do Worker (`Server-Timing: ets`) | Parede (cliente → resposta) | Observação |
|---|---|---|---|
| Local, 30 000 req a 500 req/s alvo (`results/load-local.txt`) | p50 40 ms · p95 96 ms · p99 147 ms | p50 457 ms · p95 856 ms | `wrangler dev` é um processo só e o gerador roda na mesma máquina: saturou em ~350 req/s. Serve para funcionalidade e cota, não para latência. |
| Deploy (workers.dev), {{REMOTE_N}} req a {{REMOTE_RPS}} req/s (`results/load-remote.txt`) | {{REMOTE_EDGE}} | {{REMOTE_WALL}} | Medido de São Paulo (WSL) contra a colo mais próxima. Amostra pequena para não gastar a cota do dia. |

Dentro do Worker o que custa é a chamada ao DO (RPC na mesma colo) e, na primeira requisição de
um shard novo, a espera de até 500 ms pelo ruleset ativo. HMAC + sinais ficam abaixo de 1 ms de
CPU. Assets estáticos não passam pelo DO. O timeout do DO é 10 ms (`DO_TIMEOUT_MS`): acima disso
a requisição segue com o score sem velocity (`src=fallback`), então o p95 é limitado por construção.

Resultado de todas as 30 000 requisições locais: 30 000 × HTTP 200, 0 erros, humanos 100 % ALLOW,
crawlers 100 % ALLOW, custo no mix da carga 18,1/30 (igual ao das fixtures, como esperado).

## Consumo de cota por 30 000 requisições (medido na carga local, 4 shards × 1 colo)

| Recurso | Medido/estimado | Cota Free |
|---|---|---|
| Workers requests | 30 719 (30 000 + 719 beacons de atestação) | 100 000/dia |
| DO requests | 30 148 (1 por request + 148 polls de versão) | 100 000/dia |
| KV leituras | < 60 (memo por isolate) | 100 000/dia |
| KV escritas | 0 no hot path (2 por publish; fiz 4 publishes = 8) | 1 000/dia |
| Queue operações | ~936 (312 mensagens × 3) | 10 000/dia |
| D1 linhas escritas | ~21 500 (1 batch + agregados + ≤ 60 amostras por mensagem) | 100 000/dia |
| D1 queries por invocação do consumer | 2 | 50 |

Sobra folga de 10× em Queues e de 3× em Workers/DO para a rodada de avaliação.

## Onde acho que vou perder pontos

- **Bloco A (benchmark):** estimo 18 de 30 nas minhas fixtures. Se o benchmark oculto tiver muitos
  bots com TLS de navegador real em IP residencial, não há sinal passivo que os pegue sem bloquear
  humanos; aceitei isso. Se tiver muitos `requests` com UA de Chrome, vou melhor que a estimativa.
- **Bloco B (red team):** o HTTP client com UA de Chrome (4 pts) cai em DECOY na primeira requisição
  ou na segunda (desafio ignorado + velocity). Playwright headless em datacenter (7 pts) cai por
  `HeadlessChrome`/hints ou, se mascarado, por ASN + desafio ignorado (Turnstile invisível não roda
  em headless) + velocity. Playwright stealth + proxy residencial (9 pts): só velocity, trap e
  atestação; provavelmente perco a maior parte desses 9.
- **Bloco C (latência):** o risco é a primeira requisição de cada shard na colo do avaliador
  (criação do DO + ruleset) e o DoH do primeiro crawler. Ambos acontecem uma vez; o p99 pode sentir.
- **Bloco E:** não tenho CI nem lint configurados (fora do escopo, mas um revisor pode sentir falta).
- **Custom Hostname ponta a ponta:** o código e a API existem (`src/api/cloudflare.ts`), mas o
  deploy de demonstração está só no `workers.dev`, sem zona própria; a parte do CNAME/certificado
  está documentada no README e não demonstrada ao vivo.

## Premissas que assumi (e perguntas que mandei/mandaria ao recrutador)

1. **"Humano bloqueado" inclui DECOY?** Assumi que sim (conservador). Se só BLOCK contar, dá para
   baixar `thresholds.decoy` sem risco.
2. **TikTok:** ByteDance não publica rDNS nem lista de IPs; quando o PTR não existe, trato como
   "não verificável" e libero (R1 vale mais). Como vocês verificam o TikTok no benchmark?
3. **`links` (HMAC com TTL):** interpretei como links assinados de leitura da API (ex.: compartilhar
   `/stats` com alguém sem chave). Se a intenção era "link de campanha que nunca sofre fricção",
   é uma regra `rules[]` com `verdict: ALLOW` por query string — 10 linhas.
4. **Hostname desconhecido com KV e D1 fora ao mesmo tempo e sem memo:** não existe origem para
   onde encaminhar; respondo 404. Com qualquer um dos dois de pé (ou memo quente) é ALLOW.
5. **Assets estáticos** (`.css/.js/.png/...`) passam sem score nem velocity. Se o benchmark injetar
   bots pedindo só assets, eles passam.
6. **Velocity de ASN e fingerprint é por shard** (4 por tenant/colo): limite efetivo ÷ 4.
   Por IP é exata.
7. **Contagem do X-Eval-Context:** `iat` dentro de ±300 s (aceito relógio adiantado também).
