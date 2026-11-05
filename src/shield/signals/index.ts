// Registro dos sinais. 9 sinais, 7 passivos. Todos alimentam o score via peso.
import { asnSignal } from "./asn";
import { attestationSignal } from "./attestation";
import { geoSignal } from "./geo";
import { headersSignal } from "./headers";
import { pathSignal } from "./path";
import { tlsSignal } from "./tls";
import { trapSignal } from "./trap";
import type { Signal } from "./types";
import { uaSignal } from "./ua";
import { velocitySignal } from "./velocity";

export const SIGNALS: readonly Signal[] = [
  asnSignal,
  tlsSignal,
  headersSignal,
  uaSignal,
  geoSignal,
  pathSignal,
  velocitySignal,
  trapSignal,
  attestationSignal,
];

export const PASSIVE_SIGNALS = SIGNALS.filter((s) => s.passive);

export * from "./types";
