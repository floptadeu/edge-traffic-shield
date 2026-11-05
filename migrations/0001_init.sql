-- D1 é a fonte da verdade. KV guarda a versão compilada para o hot path.

CREATE TABLE IF NOT EXISTS tenants (
  id              TEXT PRIMARY KEY,
  name            TEXT NOT NULL,
  origin          TEXT NOT NULL,            -- ex.: https://origem.cliente.com
  ruleset_version INTEGER NOT NULL DEFAULT 0,  -- ponteiro da versão ativa
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
  key_id     TEXT PRIMARY KEY,
  key_hash   TEXT NOT NULL,                  -- sha256(secret); o segredo nunca é guardado
  tenant_id  TEXT,                           -- NULL = chave admin da plataforma
  role       TEXT NOT NULL,                  -- 'admin' | 'tenant'
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS domains (
  hostname       TEXT PRIMARY KEY,
  tenant_id      TEXT NOT NULL,
  status         TEXT NOT NULL,              -- pending | active | manual | error
  cf_hostname_id TEXT,
  verification   TEXT,                       -- JSON devolvido pela API de Custom Hostnames
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_domains_tenant ON domains(tenant_id);

CREATE TABLE IF NOT EXISTS ruleset_versions (
  tenant_id  TEXT NOT NULL,
  version    INTEGER NOT NULL,
  body       TEXT NOT NULL,                  -- JSON do ruleset (imutável)
  comment    TEXT,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, version)
);

-- Idempotência do consumer: um lote só é aplicado uma vez.
CREATE TABLE IF NOT EXISTS event_batches (
  batch_id    TEXT PRIMARY KEY,
  tenant_id   TEXT NOT NULL,
  received_at INTEGER NOT NULL
);

-- Amostra de eventos individuais (100% dos não-ALLOW, 1:10 dos ALLOW).
CREATE TABLE IF NOT EXISTS events (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  ts        INTEGER NOT NULL,
  host      TEXT,
  path      TEXT,
  ip_hash   TEXT,
  asn       INTEGER,
  country   TEXT,
  colo      TEXT,
  verdict   TEXT NOT NULL,                   -- veredito calculado
  applied   TEXT NOT NULL,                   -- o que foi aplicado (ALLOW em monitor)
  score     INTEGER NOT NULL,
  signals   TEXT                             -- JSON compacto dos sinais que contribuíram
);
CREATE INDEX IF NOT EXISTS idx_events_tenant_ts ON events(tenant_id, ts DESC, id DESC);

-- Agregado exato por minuto e veredito (alimenta /stats).
CREATE TABLE IF NOT EXISTS stats_minute (
  tenant_id TEXT NOT NULL,
  minute    INTEGER NOT NULL,                -- epoch em minutos
  verdict   TEXT NOT NULL,
  n         INTEGER NOT NULL,
  score_sum INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, minute, verdict)
);
