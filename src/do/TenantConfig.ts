// Um DO por tenant guardando só o ponteiro da versão ativa do ruleset.
// É o que dá propagação <= 5 s: os shards perguntam aqui a cada 2 s em vez de
// depender da consistência eventual do KV (até 60 s).

import { DurableObject } from "cloudflare:workers";
import type { Env } from "../env";

export class TenantConfig extends DurableObject<Env> {
  private version: number | undefined;

  async getVersion(): Promise<number> {
    if (this.version === undefined) {
      this.version = (await this.ctx.storage.get<number>("version")) ?? 0;
    }
    return this.version;
  }

  async setVersion(version: number): Promise<void> {
    this.version = version;
    await this.ctx.storage.put("version", version);
  }
}
