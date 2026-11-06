# Arquitetura

## Caminho da requisição

```
visitante ──► Worker (src/shield/pipeline.ts)
   1. hostname → tenant           KV host:{hostname} (cacheTtl 60 s) + memo 30 s no isolate; fallback D1; memo vencido se tudo falhar
   2. asset estático?             passa direto (sem score, sem DO): não polui a velocity de humanos
   3. X-Eval-Context              HMAC-SHA256 (WebCrypto) + timingSafeEqual + |iat| ≤ 300 s; inválido = ignora em silêncio
   4. ruleset no Worker           KV ruleset:{tenant}:{v} (chave imutável, memo) — só para pesos/limiares do fallback
   5. sinais no Worker            asn · tls · headers · ua · geo · path · attestation (cookie assinado)   [puros, testados isolados]
   6. R1 crawler                  UA de crawler? → FCrDNS via DoH (ou AS32934 Meta), cache em memória + Cache API → ALLOW forçado
   7. UMA chamada RPC ao DO       ShieldShard(tenant, colo, hash(ip) % shards), timeout 10 ms
        └─ dentro do DO:          velocity IP/ASN/fp em janela deslizante (memória) + trap → score com o ruleset ATIVO
                                  → veredito/regras → applied (monitor ⇒ ALLOW) → evento vai para o lote (sem custo extra)
      sem resposta em 10 ms       → mesma conta no Worker sem velocity/trap (src=fallback)  [R3]
   8. aplica                      ALLOW: proxy · SILENT_VERIFY: proxy + <script> invisível · DECOY: proxy + HTMLRewriter (preços
                                  embaralhados + link-armadilha oculto) · BLOCK: 403 curto. X-Shield-Debug explica tudo.
DO ──(lote: 100 eventos ou 30 s)──► Queue ──► consumer idempotente (batch_id) ──► D1 stats_minute + amostra em events
API (/__ets/api/v1) ──► D1 (verdade) ──► KV (compilado) ──► TenantConfig DO (ponteiro de versão, lido pelos shards a cada 2 s)
```

## Cinco decisões (e o que descartei)

1. **Um DO por (tenant, colo, shard) e uma única chamada por request, que já fecha a decisão.**
   Descartado: três DOs (IP, ASN, fingerprint) = 3 chamadas = 90k das 100k req/dia do DO Free e 3× a latência;
   também um DO global por tenant = RTT intercontinental e contenção a 500 req/s. Com o shard por hash(ip)
   a contagem por IP é exata e a de ASN/fp é por shard (limite efetivo ÷ shards, documentado). Como o DO
   recebe os sinais passivos já calculados, o evento é registrado no mesmo round-trip.
2. **Velocity em memória do DO (baldes de 1 s, `SlidingCounter`), nada em SQLite.**
   Descartado: uma linha por request + `COUNT` por janela = milhares de linhas lidas por request, estoura
   as 5M linhas/dia e o p95. Custo: ao despejar o DO os contadores zeram — aceitável para rate limiting.
3. **Ruleset imutável no KV + ponteiro de versão num DO por tenant (polling de 2 s, não bloqueante).**
   Descartado: ponteiro no KV (consistência eventual de até 60 s, `cacheTtl` mínimo 60) e purge de cache
   (não confiável). Ordem do publish: D1 → `ruleset:{t}:{v}` → `rsptr` → `TenantConfig.setVersion`.
   Rollback só move o ponteiro. Medido nos testes: propagação < 5 s incluindo rollback.
4. **Eventos em lotes dentro de UMA mensagem (agregado exato + amostra), nunca uma mensagem por evento.**
   Descartado: `send()` por evento (90k operações) e `sendBatch` (cobrança é por mensagem, não por lote).
   Amostra: 100 % dos não-ALLOW, 1:10 dos ALLOW, teto de 60 por lote para ficar < 64 KB = 1 operação.
5. **Crawler verificado por rede (FCrDNS via DoH + ASN da Meta), com UA só como gatilho da consulta.**
   Descartado: rDNS em todo request (2 subrequests, mata o p95) e lista estática de IPs (desatualiza).
   Em dúvida (DNS fora, ByteDance sem rDNS publicado) o veredito é ALLOW: violar R1 reprova, liberar um bot custa 1.

Outras escolhas menores: assets estáticos não passam pelo DO; atestação amarrada ao fingerprint derivado
(cookie de um Chrome real não serve num `requests` do mesmo IP); `combine()` (noisy-OR) dentro de um sinal
para que duas pistas de 0,7 valham 0,91 e não 0,7; `DECOY` em 50 para exigir ≥ 2 indicadores fortes.

## Batching/amostragem e a conta que cabe nas cotas (rodada de 30 000 requisições)

Hipótese: 500 req/s × 50 s + 5 000 requisições espalhadas; 1 colo; 4 shards por tenant; eventos de assets não existem.

| Recurso | Conta | Uso | Cota Free/dia |
|---|---|---|---|
| Workers requests | 30 000 + beacons (≈ 50 % dos SILENT_VERIFY ≈ 1 500) + consumer (≈ 350) | ≈ 32 000 | 100 000 |
| DO requests | 1 por request + polls de versão (1 a cada 2 s × 4 shards × ~70 s ≈ 140) + alarms (≈ 20) | ≈ 30 200 | 100 000 |
| DO linhas SQLite | contadores em memória; ponteiro de versão = 1 escrita por publish | ≈ 0 | 5 M lidas / 100 k escritas |
| KV leituras | `host:` 1 por isolate a cada 30 s + `ruleset:` 1 por versão por isolate (≈ 30 isolates) | < 300 | 100 000 |
| KV escritas | 0 no hot path; 2 por publish de ruleset, 1 por domínio | ≈ 10 | 1 000 |
| Queue operações | lotes: 30 000 / 100 = 300 msgs na carga + flushes de 30 s no restante (≈ 50) = 350 msgs × 3 (write+read+delete), cada msg < 64 KB | ≈ 1 050 | 10 000 |
| D1 escritas | por mensagem: 1 batch + ≤ 8 linhas de `stats_minute` + ≤ 60 amostras ≈ 70 → 350 × 70 | ≈ 25 000 | 100 000 |
| D1 leituras | consumer: 1 SELECT de idempotência por invocação; API só sob demanda | < 10 000 | 5 M |
| D1 queries/invocação | consumer = 2 (SELECT + `batch()`, que conta como 1) | 2 | 50 |
| CPU por invocação | HMAC + sinais + serialização ≈ 1–2 ms; HTMLRewriter em streaming | < 10 ms | 10 ms |

Degradação prevista: se um dia passar de 70 % da cota de Queues, baixar `FLUSH_EVERY_EVENTS` não ajuda —
o alívio é aumentar o lote (até 64 KB) e reduzir a amostra de ALLOW (1:50); o agregado exato continua inteiro.

## Com 3 semanas

- Fingerprint real de TLS/HTTP2 (ordem de extensões, SETTINGS do h2) via Worker em TCP/`connect()` ou
  Cloudflare Snippets, em vez de só versão/cifra/tamanho do ClientHello.
- Sinais comportamentais do lado do cliente (timing de carregamento, `navigator.webdriver`, canvas) no
  mesmo beacon, com peso só para *reduzir* score (nunca para bloquear sozinhos).
- Velocity por ASN/fp global com `DurableObject` de agregação por tenant (combinando shards a cada 5 s).
- Lista de IPs oficiais do Google/Bing cacheada no KV (1 escrita/dia) como caminho rápido antes do DoH.
- Calibração de pesos por regressão logística sobre os eventos rotulados pelo próprio cliente
  (feedback "isso era humano") e relatório de FP/FN por tenant na API `stats`.
- Observabilidade: Analytics Engine para distribuição de score por sinal, alertas de degradação (`degraded=`).
