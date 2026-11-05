// Sinal "asn": origem em nuvem/hosting. Tráfego humano quase nunca sai de
// AWS/GCP/Hetzner; scrapers e headless quase sempre saem de lá.
// Cuidado: VPNs comerciais e relays (iCloud Private Relay, WARP) carregam
// humanos — por isso têm peso menor ou zero.

import type { Signal, SignalInput, SignalResult } from "./types";

// Nuvens e hosting puro: value 1.0
export const DATACENTER_ASNS = new Set<number>([
  16509, 14618, 8987, // Amazon / AWS
  396982, 19527, 15169, // Google Cloud (15169 também é o Googlebot, mas R1 roda antes)
  8075, // Microsoft Azure
  14061, // DigitalOcean
  63949, // Akamai Connected Cloud (Linode)
  20473, // Vultr / Choopa
  16276, // OVH
  24940, 213230, // Hetzner
  31898, // Oracle Cloud
  45102, 37963, // Alibaba Cloud
  132203, 45090, // Tencent Cloud
  51167, 40021, // Contabo
  60781, 28753, 395954, // Leaseweb
  12876, // Scaleway
  8560, // IONOS
  26496, // GoDaddy
  36352, // ColoCrossing
  8100, // QuadraNet
  40676, // Psychz
  46606, // Unified Layer
  55286, // Server Mania
  62240, // Clouvider
  174, // Cogent (trânsito; pouca ponta residencial)
  3842, // RamNode
  64476, 53667, // PONYNET / FranTech (BuyVM)
  47583, // Hostinger
  198610, // Beget
  211252, // Delis / hosting
  204601, 207990, // hosting diversos
]);

// VPN comercial / hosting misto: humano é plausível. value 0.5
export const VPN_ASNS = new Set<number>([
  9009, // M247
  212238, // Datacamp (NordVPN, ExpressVPN...)
  136787, // TEFINCOM (NordVPN)
  60068, // Datacamp UK
  49981, // WorldStream
  206092, // IPXO
  62651, // Mullvad (via 31898?) – mantém no misto
  200651, // FlokiNET
]);

// Relays usados por humanos: value 0
export const RELAY_ASNS = new Set<number>([
  13335, // Cloudflare (WARP, iCloud Private Relay)
  6185, 714, // Apple (Private Relay)
  20940, 16625, // Akamai (Private Relay egress)
]);

const HOSTING_WORDS = /hosting|cloud|datacenter|data center|server|vps|dedicated|colocation|colo\b|hetzner|ovh|digitalocean|linode|vultr|amazon|google llc|microsoft/i;
const RESIDENTIAL_WORDS = /telecom|telefonica|claro|vivo|tim\b|oi s\.a|comcast|verizon|at&t|vodafone|orange|deutsche telekom|bt\b|sky\b|virgin|net servicos|algar|brisanet|unifique|cable|broadband|wireless|mobile|cellular|communications/i;

export const asnSignal: Signal = {
  id: "asn",
  passive: true,
  description: "ASN de nuvem/hosting (1.0), VPN comercial (0.5), relay humano (0)",
  evaluate(input: SignalInput): SignalResult | null {
    const { asn, asOrganization } = input.conn;
    const { trusted, datacenter } = input.ruleset.asn;
    if (!asn) return null;
    if (trusted.includes(asn)) return { value: 0, reason: `trusted:${asn}` };
    if (RELAY_ASNS.has(asn)) return { value: 0, reason: `relay:${asn}` };
    if (DATACENTER_ASNS.has(asn) || datacenter.includes(asn)) return { value: 1, reason: `dc:${asn}` };
    if (VPN_ASNS.has(asn)) return { value: 0.5, reason: `vpn:${asn}` };
    // Sem o ASN na lista, usa o nome da organização como pista fraca.
    if (asOrganization) {
      if (RESIDENTIAL_WORDS.test(asOrganization)) return { value: 0, reason: "org-residential" };
      if (HOSTING_WORDS.test(asOrganization)) return { value: 0.6, reason: "org-hosting" };
    }
    return { value: 0, reason: `asn:${asn}` };
  },
};
