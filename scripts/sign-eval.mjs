// Gera um header X-Eval-Context assinado para testes manuais com curl.
//
//   node scripts/sign-eval.mjs '{"ip":"3.120.1.1","asn":16509,"asOrganization":"Amazon","country":"US","httpProtocol":"HTTP/1.1"}'
//   curl -si http://localhost:8787/landing -H "X-Shield-Host: demo.cliente.test" -H "X-Eval-Context: $(node scripts/sign-eval.mjs '{...}')"

import { loadEvalKey, parseArgs, signEvalContext } from "./lib.mjs";

const positional = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const args = parseArgs(process.argv.slice(2));
const payload = positional[0] ? JSON.parse(positional[0]) : { ip: "203.0.113.7", asn: 16509, asOrganization: "Amazon", country: "US", tlsVersion: "TLSv1.2", tlsCipher: "AES128-GCM-SHA256", tlsClientHelloLength: 512, httpProtocol: "HTTP/1.1" };
process.stdout.write(signEvalContext(payload, loadEvalKey(args["eval-key"])));
