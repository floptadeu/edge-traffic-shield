// Bindings e segredos do Worker. Mantido à mão (e não gerado) para que os
// segredos apareçam tipados mesmo sem estarem no wrangler.jsonc.
export interface Env {
  // Bindings (wrangler.jsonc)
  CONFIG_KV: KVNamespace;
  DB: D1Database;
  SHIELD_SHARD: DurableObjectNamespace<import("./do/ShieldShard").ShieldShard>;
  TENANT_CONFIG: DurableObjectNamespace<import("./do/TenantConfig").TenantConfig>;
  EVENTS_QUEUE: Queue<unknown>;

  // Vars
  DO_TIMEOUT_MS?: string;
  DEV_FEATURES?: string;
  PLATFORM_HOST?: string;
  FALLBACK_ORIGIN?: string;

  // Secrets (wrangler secret put / .dev.vars)
  EVAL_KEY?: string; // chave do avaliador para o X-Eval-Context
  ADMIN_API_KEY?: string; // chave admin da plataforma (cria tenants)
  COOKIE_SECRET?: string; // assina cookies de atestação/desafio e links HMAC
  TURNSTILE_SITE_KEY?: string;
  TURNSTILE_SECRET_KEY?: string;
  CF_API_TOKEN?: string; // Custom Hostnames (Cloudflare for SaaS)
  CF_ZONE_ID?: string;

  // Só em testes
  TEST_MIGRATIONS?: unknown;
}
