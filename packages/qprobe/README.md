# @quantakrypto/qprobe

Actively inspect **live TLS/SSH endpoints you own** for post-quantum readiness —
whether they negotiate a PQC-hybrid key exchange, and what their classical exposure
is — with **zero runtime dependencies** (Node built-ins only).

qProbe is the live-endpoint sibling of [qScan](../qscan) (which scans code) and the
infrastructure detectors in [`@quantakrypto/core`](../core) (which scan config). It
is the **only** package in this repo that opens network connections, and it is gated
behind a mandatory ownership attestation — read **[THREAT-MODEL.md](THREAT-MODEL.md)**
before using it.

> **Authorization required.** qProbe sends nothing until you attest you are
> authorized to test the target. Active probing of endpoints you do not own may be
> unlawful. qProbe refuses CIDR blocks, IP ranges, wildcards, and target lists — it
> probes **one host you operate** at a time, and it only ever performs a benign,
> unauthenticated handshake. It reports the negotiated reality; it never modifies an
> endpoint ("engine disposes").

## What it checks

- **TLS** — the negotiated TLS version, cipher suite, ephemeral key-exchange group,
  and leaf-certificate key type, **plus** whether the server supports the
  post-quantum hybrid group **X25519MLKEM768** (codepoint `0x11EC`). Because Node's
  bundled OpenSSL cannot negotiate that group, qProbe detects it with a hand-rolled
  raw ClientHello and reads the group the server selects.
- **SSH** — the offered key-exchange and host-key algorithms (from the cleartext
  `KEXINIT`), flagging classical-only servers and surfacing PQC KEX
  (`sntrup761x25519-sha512@openssh.com`, `mlkem768x25519-sha256`) as a positive.

Findings are `@quantakrypto/core` Findings, so they score (`readinessScore`) and
read exactly like qScan output and can be merged into the same posture.

## Usage

```bash
# TLS 443: hybrid KEX + certificate posture (endpoint you control)
npx @quantakrypto/qprobe --i-own-this example.com

# SSH 22: KEXINIT algorithms
npx @quantakrypto/qprobe --ssh --i-own-this git.example.com

# Multiple endpoints from an ownership manifest, JSON output
npx @quantakrypto/qprobe --owned-hosts hosts.txt api.example.com:8443 --json
```

### Options

| Flag | Meaning |
|---|---|
| `--i-own-this` | Attest you are authorized to probe the target(s). Required (or `--owned-hosts`). |
| `--owned-hosts <file>` | Ownership manifest (one host per line, `#` comments). Every target must be listed. |
| `--tls` / `--ssh` | Force a probe mode (default: auto — SSH on `:22`, TLS otherwise). |
| `--servername <name>` | TLS SNI server name (default: the host; omitted for bare IPs). |
| `--timeout <ms>` | Per-connection timeout (default: 8000). |
| `--format <human\|json>` | Output format (default: human). `--json` is an alias. |

Exit codes mirror qScan: `0` clean, `1` findings, `2` error / not authorized.

## Example

```
$ qprobe --i-own-this example.com

example.com:443  [tls]
  TLSv1.3 · TLS_AES_256_GCM_SHA384 · KEX X25519 · cert EC(prime256v1)-256
  PQC-hybrid (X25519MLKEM768): not negotiated
  [medium] Classical TLS key exchange (no PQC hybrid) — the session key is
           harvest-now-decrypt-later exposed …
  [low]    Classical certificate key — forgeable once a CRQC exists …

2 findings · 1 HNDL-exposed · readiness 90/100
```

## License

Apache-2.0. See [THREAT-MODEL.md](THREAT-MODEL.md) for the authorization model.
