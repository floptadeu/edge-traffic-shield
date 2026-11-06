// Entrypoint do Worker.
//   /__ets/api/*   -> API de gestão (tenants, domains, ruleset, events, stats, links)
//   /__ets/health  -> liveness
//   qualquer outro -> hot path (proxy com veredito)
// Queue consumer: eventos -> D1.

import { handleApi } from "./api";
import type { EventBatchMessage } from "./do/protocol";
import type { Env } from "./env";
import { brokenBinding, brokenNamespace, hangingNamespace } from "./lib/failopen";
import { consumeEvents } from "./queue/consumer";
import { handleShield } from "./shield/pipeline";

export { ShieldShard } from "./do/ShieldShard";
export { TenantConfig } from "./do/TenantConfig";

export default {
  async fetch(request, env, ctx): Promise<Response> {
    env = applyChaos(request, env);
    const url = new URL(request.url);
    if (url.pathname.startsWith("/__ets/api/")) return handleApi(request, env, ctx);
    if (url.pathname === "/__ets/health") return Response.json({ ok: true });
    return handleShield(request, env, ctx);
  },

  async queue(batch, env): Promise<void> {
    await consumeEvents(batch as MessageBatch<EventBatchMessage>, env);
  },
} satisfies ExportedHandler<Env>;

// Injeção de falha (só com DEV_FEATURES="true"):
//   X-Shield-Chaos: kv,d1,do,queue,do-hang
function applyChaos(request: Request, env: Env): Env {
  if (env.DEV_FEATURES !== "true") return env;
  const chaos = request.headers.get("x-shield-chaos");
  if (!chaos) return env;
  const broken = new Set(chaos.split(",").map((s) => s.trim()));
  const out: Env = { ...env };
  if (broken.has("kv")) out.CONFIG_KV = brokenBinding<KVNamespace>("kv");
  if (broken.has("d1")) out.DB = brokenBinding<D1Database>("d1");
  if (broken.has("do")) out.SHIELD_SHARD = brokenNamespace() as unknown as Env["SHIELD_SHARD"];
  if (broken.has("do-hang")) out.SHIELD_SHARD = hangingNamespace() as unknown as Env["SHIELD_SHARD"];
  if (broken.has("queue")) out.EVENTS_QUEUE = brokenBinding<Queue<unknown>>("queue");
  return out;
}
