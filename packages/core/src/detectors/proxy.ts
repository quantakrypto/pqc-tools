/**
 * Config detector: classical-certificate TLS termination in standalone
 * reverse-proxy / load-balancer configuration and in-code gRPC channel
 * credentials.
 *
 * A standalone Envoy, Nginx, HAProxy, Traefik, or Caddy config that terminates
 * TLS with an RSA/ECDSA leaf certificate and negotiates an ECDHE key exchange is
 * the canonical harvest-now-decrypt-later (HNDL) surface: an attacker who
 * records today's handshake + ciphertext can decrypt it retroactively once a
 * cryptographically-relevant quantum computer (CRQC) can break the ephemeral
 * (EC)DHE secret. The Kubernetes / service-mesh detectors (`k8s.ts`, `mesh.ts`)
 * cover the CLUSTER-managed cert + mesh-mTLS surfaces; the STANDALONE proxy
 * config FILES and the in-code gRPC credential constructors below are seen by
 * neither them nor the language packs, so they are covered here.
 *
 * Because the config token itself does not name the cert's key algorithm (the
 * key lives in a referenced PEM file, out of band), these findings use
 * `algorithm: "unknown"` — the evidence is "a classical-cert TLS channel is
 * configured HERE", not a specific family. They are `category: "key-exchange"`
 * (the ECDHE handshake is the harvestable primitive) and `hndl: true`.
 * Confidence is `medium`: a config-level indicator of a classical TLS channel,
 * not a matched algorithm string.
 *
 * PRECISION / fast-reject: several of the matched tokens (`ssl_certificate`,
 * `private_key:`, `certificates:`) are generic enough to appear in unrelated
 * YAML/config, so `detect()` bails unless the file carries a distinctive
 * proxy/gRPC marker (see `hasProxyMarker`). This keeps a random YAML that merely
 * has a `private_key:` key, or a Traefik-shaped `certificates:` list that isn't
 * a Traefik config, from firing. Comments are masked (YAML/nginx/HCL `#`, plus
 * `//` and C-style `/* … *\/` blocks) so a commented-out directive can't fire.
 *
 * Covered surfaces:
 *  - Envoy   — `common_tls_context:` / `DownstreamTlsContext` /
 *              `UpstreamTlsContext` with `tls_certificates:` carrying a
 *              `certificate_chain:` + `private_key:` (and the
 *              `envoy.transport_sockets.tls` transport socket).
 *  - Nginx   — `ssl_certificate` + `ssl_certificate_key` directives.
 *  - HAProxy — `bind … ssl crt …` lines and `crt-store` sections.
 *  - Traefik — a `tls:` block's `certificates:` with `certFile:` + `keyFile:`
 *              (dynamic config) or a `certResolver` (ACME) reference.
 *  - gRPC    — in-code TLS channel credentials: `grpc.ssl_channel_credentials(`
 *              (Python), `grpc.credentials.createSsl(` (Node),
 *              `TlsChannelCredentials` (Java), `credentials.NewTLS(` (Go).
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import {
  DOC_EXTENSIONS,
  eachMatch,
  findingFromRule,
  hasExtension,
  maskBlockComments,
  maskCommentLines,
} from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO } from "../cwe.js";

// --- Envoy: a downstream/upstream TLS context that references a leaf cert + key.
// `common_tls_context:` (shared by Downstream/UpstreamTlsContext) with a
// `tls_certificates:` list is the canonical shape; anchor on the distinctive
// `certificate_chain:` and `private_key:` fields that list carries. Also match
// the two `*TlsContext` type names directly, and the `tls_certificates:` key.
const RE_ENVOY_TLS =
  /\b(?:DownstreamTlsContext|UpstreamTlsContext|common_tls_context\s*:|tls_certificates\s*:|(?:certificate_chain|private_key)\s*:)/g;

// --- Nginx: the classic `ssl_certificate` / `ssl_certificate_key` directive
// pair. `ssl_certificate_key` is matched first-class; `ssl_certificate` requires
// a following space so it doesn't also swallow `ssl_certificate_key` as a second
// hit on the same directive (kept as a single rule regardless).
const RE_NGINX_TLS = /\bssl_certificate(?:_key)?\s+\S/g;

// --- HAProxy: a `bind` line that terminates TLS (`ssl crt <path>`) or a
// `crt-store` section (HAProxy 2.8+ certificate store). `ssl` and `crt` may be
// separated by other bind args, so match them independently on a bind context.
const RE_HAPROXY_TLS =
  /\bcrt-store\b|\bbind\b[^\n]*\bssl\b[^\n]*\bcrt\b|\bbind\b[^\n]*\bcrt\b[^\n]*\bssl\b/g;

// --- Traefik: dynamic-config TLS certificate entries (`certFile:` + `keyFile:`)
// or an ACME `certResolver` reference. `certFile`/`keyFile` are Traefik-specific
// enough (paired with the `certResolver`/`tls:` marker gate) to anchor on.
const RE_TRAEFIK_TLS = /\bcertResolver\b|\b(?:certFile|keyFile)\s*:/g;

// --- gRPC in-code TLS channel credentials across languages.
const RE_GRPC_TLS =
  /grpc\.ssl_channel_credentials\s*\(|grpc\.credentials\.createSsl\s*\(|\bTlsChannelCredentials\b|\bcredentials\.NewTLS\s*\(/g;

const MESSAGE = (proxy: string): string =>
  `${proxy} terminates TLS with a classical certificate + ECDHE key exchange; the recorded handshake is harvest-now-decrypt-later exposed — verify the cert key algorithm and plan a PQC-hybrid (X25519MLKEM768) TLS migration.`;

const REMEDIATION =
  "Enable hybrid PQC key exchange (X25519MLKEM768) once the proxy/gRPC stack supports it; re-key certificates to PQC signatures (ML-DSA) when available.";

const RULE_ENVOY: RuleMeta = {
  id: "proxy-envoy-tls",
  title: "Envoy classical TLS termination",
  description: "Envoy TLS context terminates TLS with a classical certificate + ECDHE key exchange",
  category: "key-exchange",
  severity: "medium",
  confidence: "medium",
  algorithm: "unknown",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: MESSAGE("Envoy"),
  remediation: REMEDIATION,
};
const RULE_NGINX: RuleMeta = {
  id: "proxy-nginx-tls",
  title: "Nginx classical TLS termination",
  description:
    "Nginx ssl_certificate/ssl_certificate_key terminates TLS with a classical cert + ECDHE",
  category: "key-exchange",
  severity: "medium",
  confidence: "medium",
  algorithm: "unknown",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: MESSAGE("Nginx"),
  remediation: REMEDIATION,
};
const RULE_HAPROXY: RuleMeta = {
  id: "proxy-haproxy-tls",
  title: "HAProxy classical TLS termination",
  description: "HAProxy bind ssl crt / crt-store terminates TLS with a classical cert + ECDHE",
  category: "key-exchange",
  severity: "medium",
  confidence: "medium",
  algorithm: "unknown",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: MESSAGE("HAProxy"),
  remediation: REMEDIATION,
};
const RULE_TRAEFIK: RuleMeta = {
  id: "proxy-traefik-tls",
  title: "Traefik classical TLS termination",
  description:
    "Traefik tls certificates (certFile/keyFile) or certResolver terminate TLS with a classical cert + ECDHE",
  category: "key-exchange",
  severity: "medium",
  confidence: "medium",
  algorithm: "unknown",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: MESSAGE("Traefik"),
  remediation: REMEDIATION,
};
const RULE_GRPC: RuleMeta = {
  id: "grpc-tls-credentials",
  title: "gRPC classical TLS channel credentials",
  description: "gRPC channel established with classical TLS credentials (RSA/ECDSA cert + ECDHE)",
  category: "key-exchange",
  severity: "medium",
  confidence: "medium",
  algorithm: "unknown",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: MESSAGE("gRPC"),
  remediation: REMEDIATION,
};

/**
 * Distinctive proxy/gRPC markers. `detect()` bails unless the (comment-masked)
 * content carries one, so generic tokens (`ssl_certificate`, `private_key:`)
 * can't fire on unrelated config. Deliberately strict: a bare `private_key:` in
 * a random YAML, or a plain `certificates:` list, has NO marker here.
 */
const PROXY_MARKERS: readonly string[] = [
  "common_tls_context",
  "DownstreamTlsContext",
  "UpstreamTlsContext",
  "envoy.transport_sockets.tls",
  "ssl_certificate",
  "ssl_certificate_key",
  "crt-store",
  "certResolver",
  "grpc.ssl_channel_credentials",
  "createSsl",
  "TlsChannelCredentials",
  // Go grpc TLS transport credentials — was matched by the rule but not gated in.
  "credentials.NewTLS",
];

interface ProxyRule {
  meta: RuleMeta;
  re: RegExp;
}

const PROXY_RULES: readonly ProxyRule[] = [
  { meta: RULE_ENVOY, re: RE_ENVOY_TLS },
  { meta: RULE_NGINX, re: RE_NGINX_TLS },
  { meta: RULE_HAPROXY, re: RE_HAPROXY_TLS },
  { meta: RULE_TRAEFIK, re: RE_TRAEFIK_TLS },
  { meta: RULE_GRPC, re: RE_GRPC_TLS },
];

/**
 * Detects classical-cert TLS termination in standalone reverse-proxy /
 * load-balancer config files and in-code gRPC channel credentials. See the
 * module docstring for the covered surfaces and the fast-reject rationale.
 */
export const proxyDetector: Detector = {
  id: "proxy-tls-crypto",
  description:
    "Classical-cert TLS termination in reverse-proxy / load-balancer config (Envoy, Nginx, HAProxy, Traefik) and gRPC channel credentials",
  scope: "config",
  language: "any",
  rules: PROXY_RULES.map((r) => r.meta),
  // Config + source files are all in scope (gRPC creds live in code); only prose
  // documentation is excluded, so a README mentioning `ssl_certificate` in a
  // sentence can't fire (the marker gate already handles most of this).
  appliesTo: (f) => !hasExtension(f, DOC_EXTENSIONS),
  detect({ file, content }): Finding[] {
    // Mask comments first, THEN gate: a proxy marker that appears only inside a
    // commented-out block must not un-gate the file.
    const scan = maskCommentLines(maskBlockComments(content), ["#", "//"]);
    if (!PROXY_MARKERS.some((mk) => scan.includes(mk))) return [];

    const findings: Finding[] = [];
    for (const { meta, re } of PROXY_RULES) {
      eachMatch(re, scan, (m) =>
        findings.push(
          findingFromRule(meta, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );
    }
    return findings;
  },
};
