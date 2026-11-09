import path from "node:path";
import { defineConfig } from "vitest/config";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";

// Os testes rodam DENTRO do runtime Workers (miniflare), com KV, D1, DO e Queue locais.
export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(import.meta.dirname, "migrations"));
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
            DEV_FEATURES: "true",
            // Em teste a API responde em qualquer host; a restrição por host tem teste próprio.
            PLATFORM_HOST: "",
            // Em teste o DO local pode demorar mais que 10 ms a frio; o timeout curto é testado com do-hang.
            DO_TIMEOUT_MS: "2000",
          },
        },
      }),
    ],
  };
});
