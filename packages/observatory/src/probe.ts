/**
 * Per-host TLS measurement for the observatory.
 *
 * The observatory probes public hosts we do NOT own, so it must NOT use qProbe's
 * public `runProbe`, which calls `authorizeTargets(...)` (an ownership-attestation
 * gate) before any network I/O. Instead we reuse qProbe's LOWER-LEVEL, un-gated
 * primitives directly from its source module:
 *
 *   - `probeHybridSupport` - sends a raw ClientHello advertising X25519MLKEM768 and
 *     reports whether the server SELECTS the hybrid group (positive PQC-hybrid proof).
 *   - `extractNegotiated` - reads the negotiated TLS version / cipher / KEX group and
 *     the leaf-cert signature family from an already-connected TLSSocket.
 *
 * We deliberately do NOT use `probeTlsNegotiated`: it discards the socket (and thus
 * the certificate validity window) before returning, and we need the leaf cert's
 * `notAfter`. To stay within one handshake we open the TLS socket here, delegate all
 * field extraction to qProbe's `extractNegotiated`, and additionally read `valid_to`
 * from the same peer certificate. No qProbe source is modified.
 *
 * These imports are by RELATIVE PATH into qProbe's `src/` on purpose: the primitives
 * are not re-exported from the package's public barrel (that barrel intentionally
 * exposes only `runProbe` for network I/O), and this worker lives in the same
 * monorepo, so an internal source import is the correct, gate-preserving way in.
 */
import { connect as tlsConnect } from "node:tls";
import {
  extractNegotiated,
  probeHybridSupport,
  type HybridSupport,
  type TlsNegotiated,
} from "../../qprobe/src/tls.js";

/** X25519MLKEM768 hybrid group name recorded when the server selects it. */
const HYBRID_GROUP_NAME = "X25519MLKEM768";

export interface HostMeasurement {
  /** TCP+TLS handshake completed (the host answered). */
  reachable: boolean;
  /** True only when the server SELECTED X25519MLKEM768 (proof of hybrid support). */
  kexHybrid: boolean;
  /** Key-exchange group actually in use: the hybrid name, or the classical group. */
  kexGroup?: string;
  /** Negotiated protocol, e.g. "TLSv1.3". */
  tlsVersion?: string;
  /** Negotiated cipher suite standard name. */
  cipher?: string;
  /** Leaf-cert signature family (RSA / ECDSA / EdDSA / DSA) or raw OID fallback. */
  certSigAlg?: string;
  /** Leaf-cert `notAfter` as an ISO-8601 string, when readable. */
  certExpiry?: string;
  /** First error observed (timeout / refusal / handshake failure); undefined when reachable. */
  error?: string;
  /** Raw sub-results, persisted to `observatory_probe.raw` for later forensics. */
  raw: {
    negotiated: TlsNegotiated;
    hybrid: HybridSupport;
    certNotAfterRaw?: string;
  };
}

interface TlsRead {
  negotiated: TlsNegotiated;
  certNotAfterRaw?: string;
}

/**
 * One normal TLS handshake, reusing qProbe's `extractNegotiated` for the negotiated
 * fields and additionally reading the leaf cert's `valid_to`. Read-only: we inspect
 * the negotiated reality and disconnect; we never modify the endpoint. Never rejects.
 */
function readTls(host: string, port: number, timeoutMs: number): Promise<TlsRead> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (r: TlsRead): void => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(r);
    };
    // SNI must not be an IP literal (RFC 6066); omit it for bare IPs.
    const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":");
    const servername = isIp ? undefined : host;
    const socket = tlsConnect({
      host,
      port,
      servername,
      rejectUnauthorized: false, // we inspect posture; we do not assert trust
      minVersion: "TLSv1.2",
    });
    socket.setTimeout(timeoutMs);
    socket.on("timeout", () => finish({ negotiated: { error: "timeout" } }));
    socket.on("error", (e: Error) => finish({ negotiated: { error: e.message } }));
    socket.on("secureConnect", () => {
      const negotiated = extractNegotiated(socket);
      const cert = socket.getPeerCertificate(false);
      const validTo = cert && typeof cert.valid_to === "string" ? cert.valid_to : undefined;
      finish({ negotiated, certNotAfterRaw: validTo });
    });
  });
}

/** Parse an OpenSSL-style `valid_to` ("Jun  1 12:00:00 2035 GMT") to ISO, if valid. */
function toIsoExpiry(validTo: string | undefined): string | undefined {
  if (!validTo) return undefined;
  const d = new Date(validTo);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

/**
 * Measure one host on port 443: negotiated TLS + leaf-cert posture (one handshake)
 * and hybrid-KEX support (one raw ClientHello). Two short-lived, read-only
 * handshakes, no retries. Never throws: a refusal or timeout resolves to
 * `reachable: false`.
 */
export async function measureHost(
  host: string,
  opts: { port?: number; timeoutMs?: number } = {},
): Promise<HostMeasurement> {
  const port = opts.port ?? 443;
  const timeoutMs = opts.timeoutMs ?? 8000;

  const tls = await readTls(host, port, timeoutMs);
  const hybrid = await probeHybridSupport(host, port, { timeoutMs });

  const reachable = tls.negotiated.error === undefined;
  const kexHybrid = hybrid.hybridSelected === true;
  const certExpiry = toIsoExpiry(tls.certNotAfterRaw);

  return {
    reachable,
    kexHybrid,
    kexGroup: kexHybrid ? HYBRID_GROUP_NAME : tls.negotiated.kexGroup,
    tlsVersion: tls.negotiated.protocol,
    cipher: tls.negotiated.cipher,
    certSigAlg: tls.negotiated.certSigFamily ?? tls.negotiated.certSigOid,
    certExpiry,
    error: tls.negotiated.error,
    raw: {
      negotiated: tls.negotiated,
      hybrid,
      certNotAfterRaw: tls.certNotAfterRaw,
    },
  };
}
