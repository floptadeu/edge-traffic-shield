// Sinal "path": caminhos que humanos não digitam (sondagem de vulnerabilidade,
// arquivos de crawler). Assets estáticos não entram.

import type { Signal, SignalInput, SignalResult } from "./types";

const PROBE_RE =
  /(^|\/)(\.env|\.git|\.aws|\.ssh|wp-login\.php|wp-admin|xmlrpc\.php|phpmyadmin|phpinfo|actuator|server-status|cgi-bin|\.DS_Store|config\.(php|json|yml)|backup\.(zip|sql|tar))(\/|$|\?)/i;
const CRAWL_FILES_RE = /^\/(robots\.txt|sitemap[^/]*\.xml|feed|rss|\.well-known\/security\.txt)$/i;
const STATIC_RE = /\.(css|js|mjs|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|map|mp4|webm)$/i;

export const pathSignal: Signal = {
  id: "path",
  passive: true,
  description: "Sondagem de vulnerabilidades e arquivos de crawler",
  evaluate(input: SignalInput): SignalResult | null {
    const path = input.url.pathname;
    if (STATIC_RE.test(path)) return null;
    if (PROBE_RE.test(path)) return { value: 1, reason: "probe" };
    if (CRAWL_FILES_RE.test(path)) return { value: 0.6, reason: "crawl-file" };
    if (input.method !== "GET" && input.method !== "POST" && input.method !== "HEAD") return { value: 0.4, reason: `method:${input.method}` };
    return { value: 0, reason: "ok" };
  },
};
