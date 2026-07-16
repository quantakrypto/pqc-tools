# qProbe threat model

qProbe is the only `@quantakrypto/*` package that opens network connections to
systems it did not create. Every other tool reads files you already have; qProbe
reaches out and touches a live endpoint. That single difference is the whole reason
this document exists, and it drives the design.

## Authorization is the primary control

**qProbe refuses to send a single byte to any endpoint until the operator has
attested authorization.** This is enforced in code (`authorizeTargets` in
`src/attest.ts`), not by a prompt or a README warning, and it runs **before any
socket is opened** — `runProbe` calls the gate first and throws `AttestationError`
on failure, so no connection attempt happens on the unauthorized path.

Authorization is exactly one of:

- `--i-own-this` — an explicit per-run attestation that you control the target(s).
- `--owned-hosts <file>` — an ownership manifest (one host per line); every target
  host must appear in it, or the run is refused.

There is no third path and no default-on. A run with neither flag exits non-zero
and connects to nothing.

### Scope is one host at a time

qProbe **refuses CIDR blocks, IP ranges, wildcards, and target lists** outright
(`parseTarget` in `src/target.ts`). `10.0.0.0/24`, `10.0.0.1-50`, `*.example.com`,
and `a.com,b.com` are all rejected before parsing. This is deliberate: mass scanning
is a categorically different activity from checking an endpoint you operate, and the
tool will not make it convenient. Probes are sequential with a minimum interval
between connections.

### Legal note (operator responsibility)

Actively probing endpoints you do not own or lack permission to test may violate the
US Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent
laws elsewhere, as well as your provider's acceptable-use policy. The attestation is
your assertion that you are authorized; qProbe cannot verify it for you. **You are
responsible for the legality of every target you pass.**

## What qProbe actually does on the wire

- **TLS:** one normal TLS 1.3 handshake (`node:tls`) to read the negotiated
  version / cipher / key-exchange group and the leaf certificate's public metadata;
  plus one raw ClientHello (`node:net`) advertising `X25519MLKEM768` to observe the
  group the server selects. Both are ordinary, unauthenticated handshakes — the same
  thing any browser or `openssl s_client` does. qProbe does **not** complete the
  handshake with real key material, send application data, attempt authentication,
  or exercise any vulnerability.
- **SSH:** it reads the server's cleartext identification banner and the
  `SSH_MSG_KEXINIT` it sends before encryption, to list offered key-exchange and
  host-key algorithms. **No authentication is attempted; no crypto is performed.**

**"Engine disposes."** qProbe reports the negotiated reality. It never modifies,
reconfigures, or writes to an endpoint. It has no capability to do so.

## Data handling

- The only data qProbe reads is **already public by construction**: negotiated
  protocol parameters, a server certificate (served to every client), and an SSH
  banner + algorithm name-lists (sent to every client before auth).
- qProbe captures **no secret or key material**. It does not read private keys,
  credentials, or application data. Findings carry only `host:port`, the negotiated
  parameters, and the readiness classification.
- There is no telemetry and no network egress other than to the attested target(s).

## Non-goals

- qProbe is **not** a vulnerability scanner, exploit framework, or penetration-testing
  tool. It classifies post-quantum readiness of the key exchange, cipher, and
  certificate; it does not test for CVEs or attempt compromise.
- It is **not** a discovery tool. It will not enumerate hosts, sweep ranges, or find
  endpoints for you — you bring the specific endpoint you operate.

## Residual risks & mitigations

| Risk | Mitigation |
|---|---|
| Operator probes a third-party endpoint | Attestation is required and is the operator's explicit, logged assertion; CIDR/range/list refused; legal responsibility documented. |
| Accidental mass scan | CIDR/range/wildcard/list rejected at parse time; sequential probing with a minimum interval. |
| Endpoint mistakes the probe for an attack | Probes are single, benign, standards-compliant handshakes; no auth, no app data, no exploitation. |
| Sensitive data captured | Only public handshake/cert/banner data is read; no key/secret material; findings hold only `host:port` + negotiated parameters. |
