// Placeholder temporário; substituído pelo pipeline real.
import { DurableObject } from "cloudflare:workers";
import type { Env } from "./env";

export class ShieldShard extends DurableObject<Env> {}
export class TenantConfig extends DurableObject<Env> {}

export default {
  async fetch(): Promise<Response> {
    return new Response("ok");
  },
} satisfies ExportedHandler<Env>;
