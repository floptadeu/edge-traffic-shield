// Fail-open (R3): toda dependência do hot path passa por aqui.
// Erro ou timeout => devolve `fallback` e registra o motivo em `degraded`,
// que vai parar no header de debug. Nunca lança.

export interface Degradation {
  dep: string; // kv | do | d1 | queue | origin | doh
  reason: string; // timeout | error:<msg>
}

export class DegradedLog {
  readonly items: Degradation[] = [];
  add(dep: string, reason: string): void {
    this.items.push({ dep, reason: reason.slice(0, 80) });
  }
  get empty(): boolean {
    return this.items.length === 0;
  }
  toString(): string {
    return this.items.map((d) => `${d.dep}=${d.reason}`).join(",");
  }
}

export async function safe<T>(
  dep: string,
  p: Promise<T>,
  fallback: T,
  log: DegradedLog,
  timeoutMs?: number,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    if (timeoutMs === undefined) return await p;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("timeout")), timeoutMs);
    });
    return await Promise.race([p, timeout]);
  } catch (err) {
    log.add(dep, err instanceof Error ? err.message : String(err));
    return fallback;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

// Injeção de falha para testes e demo: devolve um proxy do binding em que
// TODO método assíncrono rejeita. Só é ligado quando CHAOS_ENABLED="true".
export function brokenBinding<T extends object>(name: string): T {
  return new Proxy({} as T, {
    get(_t, prop) {
      if (prop === "then") return undefined;
      return (..._args: unknown[]) => Promise.reject(new Error(`chaos:${name}.${String(prop)}`));
    },
  });
}

// Stub de DO que nunca responde (simula DO sobrecarregado/sem resposta).
export function hangingNamespace(): DurableObjectNamespace {
  const never = () => new Promise<never>(() => {});
  const stub = new Proxy({}, { get: (_t, prop) => (prop === "then" ? undefined : never) }) as unknown as DurableObjectStub;
  return {
    idFromName: () => ({ toString: () => "hang" }) as unknown as DurableObjectId,
    get: () => stub,
  } as unknown as DurableObjectNamespace;
}
