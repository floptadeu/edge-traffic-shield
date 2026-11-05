import path from "node:path";
import { defineConfig } from "vitest/config";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";

// Os testes rodam DENTRO do runtime Workers (miniflare), com KV, D1, DO e Queue locais.
export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(__dirname, "migrations"));
  return {
    test: {
      setupFiles: ["./test/setup.ts"],
      include: ["test/**/*.test.ts"],
    },
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: {
          bindings: {
            TEST_MIGRATIONS: migrations,
            // Segredos de TESTE. Os reais nunca entram no repo.
            EVAL_KEY: "test-eval-key",
            ADMIN_API_KEY: "ets_admin_test_key",
            COOKIE_SECRET: "test-cookie-secret",
            CHAOS_ENABLED: "true",
          },
        },
      }),
    ],
  };
});
