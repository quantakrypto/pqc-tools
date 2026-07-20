/**
 * Tests for the reverse-proxy / load-balancer TLS + gRPC detector — classical
 * certificate TLS termination in standalone Envoy / Nginx / HAProxy / Traefik
 * config FILES and in-code gRPC channel credentials, a harvest-now-decrypt-later
 * (HNDL) surface neither the k8s / mesh config detectors nor the language packs
 * see. Imports the detector DIRECTLY (it is exercised in isolation).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { proxyDetector } from "../src/detectors/proxy.js";
import type { Finding } from "../src/index.js";

function run(file: string, content: string): Finding[] {
  if (!proxyDetector.appliesTo(file)) return [];
  return proxyDetector.detect({ file, content });
}
function rule(findings: Finding[], id: string): Finding | undefined {
  return findings.find((f) => f.ruleId === id);
}

test("Envoy common_tls_context with tls_certificates/private_key fires proxy-envoy-tls (key-exchange, hndl:true)", () => {
  const cfg = [
    "transport_socket:",
    "  name: envoy.transport_sockets.tls",
    "  typed_config:",
    '    "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext',
    "    common_tls_context:",
    "      tls_certificates:",
    "        - certificate_chain:",
    "            filename: /etc/envoy/cert.pem",
    "          private_key:",
    "            filename: /etc/envoy/key.pem",
  ].join("\n");
  const found = rule(run("envoy.yaml", cfg), "proxy-envoy-tls");
  assert.ok(found, "Envoy TLS context is detected");
  assert.equal(found?.category, "key-exchange");
  assert.equal(found?.algorithm, "unknown");
  assert.equal(found?.hndl, true);
  assert.equal(found?.confidence, "medium");
  assert.equal(found?.severity, "medium");
});

test("Nginx ssl_certificate + ssl_certificate_key fires proxy-nginx-tls", () => {
  const cfg = [
    "server {",
    "    listen 443 ssl;",
    "    server_name example.com;",
    "    ssl_certificate     /etc/ssl/cert.pem;",
    "    ssl_certificate_key /etc/ssl/key.pem;",
    "    ssl_ecdh_curve      secp384r1;",
    "}",
  ].join("\n");
  const found = run("nginx.conf", cfg).filter((f) => f.ruleId === "proxy-nginx-tls");
  assert.ok(found.length >= 1, "nginx TLS directives are detected");
  assert.equal(found[0]?.category, "key-exchange");
  assert.equal(found[0]?.hndl, true);
  assert.equal(found[0]?.algorithm, "unknown");
});

test("HAProxy crt-store fires proxy-haproxy-tls", () => {
  const cfg = [
    "crt-store web",
    "    crt-base /etc/haproxy/certs",
    "    load crt-list webcerts.list",
    "",
    "frontend fe_main",
    "    bind :443 ssl crt /etc/haproxy/certs/site.pem",
    "    default_backend be_main",
  ].join("\n");
  const found = run("haproxy.cfg", cfg).filter((f) => f.ruleId === "proxy-haproxy-tls");
  assert.ok(found.length >= 1, "HAProxy TLS bind / crt-store is detected");
  assert.equal(found[0]?.category, "key-exchange");
  assert.equal(found[0]?.hndl, true);
});

test("Traefik tls certificates (certResolver + certFile/keyFile) fires proxy-traefik-tls", () => {
  const cfg = [
    "entryPoints:",
    "  websecure:",
    "    address: ':443'",
    "    http:",
    "      tls:",
    "        certResolver: letsencrypt",
    "tls:",
    "  certificates:",
    "    - certFile: /etc/traefik/cert.pem",
    "      keyFile: /etc/traefik/key.pem",
  ].join("\n");
  const found = run("traefik.yml", cfg).filter((f) => f.ruleId === "proxy-traefik-tls");
  assert.ok(found.length >= 1, "Traefik TLS certificate config is detected");
  assert.equal(found[0]?.category, "key-exchange");
  assert.equal(found[0]?.hndl, true);
});

test("Python gRPC ssl_channel_credentials fires grpc-tls-credentials", () => {
  const src = [
    "import grpc",
    "with open('ca.pem', 'rb') as f:",
    "    root = f.read()",
    "creds = grpc.ssl_channel_credentials(root)",
    "channel = grpc.secure_channel('svc:443', creds)",
  ].join("\n");
  const found = rule(run("client.py", src), "grpc-tls-credentials");
  assert.ok(found, "gRPC TLS channel credentials are detected");
  assert.equal(found?.category, "key-exchange");
  assert.equal(found?.hndl, true);
  assert.equal(found?.algorithm, "unknown");
});

test("Node gRPC createSsl and Java/Go credentials also fire grpc-tls-credentials", () => {
  const node = "const creds = grpc.credentials.createSsl(rootCert);";
  assert.ok(rule(run("client.js", node), "grpc-tls-credentials"), "Node createSsl");

  const java = "ChannelCredentials creds = TlsChannelCredentials.newBuilder().build();";
  assert.ok(rule(run("Client.java", java), "grpc-tls-credentials"), "Java TlsChannelCredentials");

  // Go grpc: credentials.NewTLS is both a rule trigger AND a fast-reject marker.
  const go = "creds := credentials.NewTLS(&tls.Config{})";
  assert.ok(rule(run("server.go", go), "grpc-tls-credentials"), "Go credentials.NewTLS");
});

test("negative: random YAML with private_key but NO proxy marker fires nothing", () => {
  const yaml = [
    "database:",
    "  host: db.internal",
    "  private_key: /secrets/db.key",
    "  certificate_chain: /secrets/db.pem",
  ].join("\n");
  // `certificate_chain:`/`private_key:` are Envoy-token-shaped, but with no
  // proxy/gRPC marker in the document the strict fast-reject bails.
  assert.deepEqual(run("db-config.yaml", yaml), []);
});

test("negative: prose documentation (.md) is never scanned", () => {
  const md = [
    "# TLS setup",
    "",
    "Configure `ssl_certificate` and `ssl_certificate_key` in your nginx server block,",
    "then call `grpc.ssl_channel_credentials(root)` from the client.",
  ].join("\n");
  assert.deepEqual(run("README.md", md), []);
});

test("negative: commented-out proxy directives do not fire", () => {
  const cfg = [
    "server {",
    "    # ssl_certificate     /etc/ssl/cert.pem;",
    "    # ssl_certificate_key /etc/ssl/key.pem;",
    "    listen 80;",
    "}",
  ].join("\n");
  // The only proxy markers are inside comments → masked before the gate → no findings.
  assert.deepEqual(run("nginx.conf", cfg), []);
});

test("negative: a nginx-shaped ssl_certificate marker inside a block comment does not un-gate", () => {
  const cfg = [
    "/* legacy config",
    "   ssl_certificate /old/cert.pem;",
    "   ssl_certificate_key /old/key.pem;",
    "*/",
    "listen: 8080",
  ].join("\n");
  assert.deepEqual(run("service.conf", cfg), []);
});

test("audit H1/H2/L1: canonical HAProxy/Traefik/Envoy configs without the old narrow marker still fire", () => {
  // HAProxy: a plain `bind … ssl … crt` with no `crt-store` (the common form).
  assert.ok(
    rule(
      run("haproxy.cfg", "frontend fe_https\n  bind :443 ssl crt /etc/haproxy/site.pem"),
      "proxy-haproxy-tls",
    ),
    "HAProxy bind ssl crt fires without crt-store",
  );
  // Traefik: self-managed certFile/keyFile with no ACME `certResolver`.
  assert.ok(
    rule(
      run("dynamic.yml", "tls:\n  certificates:\n    - certFile: /c.crt\n      keyFile: /c.key"),
      "proxy-traefik-tls",
    ),
    "Traefik certFile/keyFile fires without certResolver",
  );
  // Envoy: a DownstreamTlsContext fragment (a distinctive token IS the evidence).
  assert.ok(
    rule(
      run("envoy-frag.yaml", "typed_config: DownstreamTlsContext\n  tls_certificates: []"),
      "proxy-envoy-tls",
    ),
    "Envoy fragment fires on a distinctive token",
  );
});

test("audit L2: a generic `private_key:` does NOT cross-label a non-Envoy file as Envoy", () => {
  const findings = run("nginx.conf", "server { ssl_certificate /a.pem; }\nprivate_key: /k.pem\n");
  assert.ok(rule(findings, "proxy-nginx-tls"), "nginx rule fires");
  assert.equal(rule(findings, "proxy-envoy-tls"), undefined, "no spurious Envoy attribution");
  // And a bare private_key: in unrelated YAML still fires nothing.
  assert.deepEqual(run("app.yml", "database:\n  private_key: /k.pem\n"), []);
});
