import { applyD1Migrations, env } from "cloudflare:test";

// Aplica as migrations do D1 antes de cada arquivo de teste (storage isolado por teste).
await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
