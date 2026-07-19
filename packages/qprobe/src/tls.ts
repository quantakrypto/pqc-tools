/**
 * TLS endpoint inspection. Two engines:
 *  1. `probeTlsNegotiated` — a normal `node:tls` handshake to read what the server
 *     actually negotiates: TLS version, cipher suite, ephemeral key-exchange group
 *     (the harvestable part), and the leaf certificate's public-key type/size.
 *  2. `probeHybridSupport` — a raw ClientHello (clienthello.ts) advertising
 *     X25519MLKEM768, to detect PQC-HYBRID support that Node's bundled OpenSSL
 *     cannot itself negotiate.
 *
 * `engine disposes`: we read the negotiated reality and disconnect; we never
 * modify the endpoint.
 */
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { connect as netConnect } from "node:net";
import {
  buildClientHello,
  readServerHello,
  GROUP_X25519MLKEM768,
  type ServerHelloInfo,
} from "./clienthello.js";
import { certSignatureAlgorithm } from "./x509.js";

export interface TlsNegotiated {
  protocol?: string;
  cipher?: string;
  /** Ephemeral key-exchange group, e.g. "X25519", "P-256", "DH". */
  kexGroup?: string;
  kexType?: string;
  /** Leaf certificate public-key summary. */
  certKeyType?: string;
  certKeyBits?: number;
  certSubject?: string;
  /** How the leaf certificate is SIGNED (the CA's algorithm) — e.g. "RSA", "ECDSA". */
  certSigFamily?: string;
  certSigOid?: string;
  error?: string;
}

/** Read the negotiated parameters + leaf-cert posture from a connected TLS socket. */
export function extractNegotiated(socket: TLSSocket): TlsNegotiated {
  const cipher = socket.getCipher();
  const kex = socket.getEphemeralKeyInfo();
  const cert = socket.getPeerCertificate(false);
  const cn = cert?.subject?.CN;
  // node:tls exposes the public-key type but not how the leaf was SIGNED; read the
  // signature algorithm (the forgeable-at-Q-day part) from the raw DER.
  const sig = cert?.raw ? certSignatureAlgorithm(cert.raw) : undefined;
  return {
    protocol: socket.getProtocol() ?? undefined,
    cipher: cipher?.standardName ?? cipher?.name,
    kexGroup: kex && "name" in kex ? kex.name : undefined,
    kexType: kex && "type" in kex ? kex.type : undefined,
    certKeyType: cert?.asn1Curve ? `EC(${cert.asn1Curve})` : cert?.pubkey ? "RSA" : undefined,
    certKeyBits: typeof cert?.bits === "number" ? cert.bits : undefined,
    certSubject: Array.isArray(cn) ? cn[0] : cn,
    certSigFamily: sig?.family,
    certSigOid: sig?.oid,
  };
}

/** Perform a normal TLS handshake and read the negotiated parameters. */
export function probeTlsNegotiated(
  host: string,
  port: number,
  opts: { servername?: string; timeoutMs?: number } = {},
): Promise<TlsNegotiated> {
  const timeoutMs = opts.timeoutMs ?? 8000;
  return new Promise((resolve) => {
    let done = false;
    const finish = (r: TlsNegotiated) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(r);
    };
    // SNI must not be an IP literal (RFC 6066); omit it for bare IPs.
    const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":");
    const servername = opts.servername ?? (isIp ? undefined : host);
    const socket = tlsConnect({
      host,
      port,
      servername,
      rejectUnauthorized: false, // we inspect posture; we do not assert trust
      minVersion: "TLSv1.2",
    });
    socket.setTimeout(timeoutMs);
    socket.on("timeout", () => finish({ error: "timeout" }));
    socket.on("error", (e) => finish({ error: e.message }));
    socket.on("secureConnect", () => {
      finish(extractNegotiated(socket));
    });
  });
}

export interface HybridSupport {
  /** True only when the server SELECTED the hybrid group (proof of support). */
  hybridSelected: boolean;
  selectedGroup?: number;
  isHelloRetryRequest?: boolean;
  negotiatedVersion?: number;
  error?: string;
}

/**
 * Send a raw ClientHello advertising X25519MLKEM768 and read the group the server
 * selects. A server that supports+prefers the hybrid group answers with a
 * HelloRetryRequest selecting 0x11EC — positive proof of PQC-hybrid support.
 */
export function probeHybridSupport(
  host: string,
  port: number,
  opts: { servername?: string; timeoutMs?: number } = {},
): Promise<HybridSupport> {
  const timeoutMs = opts.timeoutMs ?? 8000;
  return new Promise((resolve) => {
    let buf = Buffer.alloc(0);
    let done = false;
    const finish = (r: HybridSupport) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(r);
    };
    const socket = netConnect({ host, port });
    socket.setTimeout(timeoutMs);
    socket.on("connect", () => {
      socket.write(buildClientHello({ serverName: opts.servername ?? host }));
    });
    socket.on("timeout", () => finish({ hybridSelected: false, error: "timeout" }));
    socket.on("error", (e) => finish({ hybridSelected: false, error: e.message }));
    // Clean close before a ServerHello would otherwise hang the Promise (the timeout
    // does not fire post-close). Guarded by `done` so a normal finish wins.
    socket.on("close", () => finish({ hybridSelected: false, error: "connection closed" }));
    socket.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      let sh: ServerHelloInfo | undefined;
      try {
        sh = readServerHello(buf);
      } catch {
        // A hostile or broken endpoint can send a length-consistent but internally
        // truncated ServerHello, which trips the parser's bounds check. readServerHello
        // only parses a handshake body that is already fully present, so a throw means
        // the message is malformed, not merely incomplete — finish gracefully instead
        // of letting the RangeError escape this data handler as an uncaught exception
        // (which would crash the process). Mirrors the guarded parse in ssh.ts.
        finish({ hybridSelected: false, error: "malformed ServerHello" });
        return;
      }
      if (!sh) {
        if (buf.length > 64 * 1024) finish({ hybridSelected: false, error: "no ServerHello" });
        return;
      }
      finish({
        hybridSelected: sh.selectedGroup === GROUP_X25519MLKEM768,
        selectedGroup: sh.selectedGroup,
        isHelloRetryRequest: sh.isHelloRetryRequest,
        negotiatedVersion: sh.negotiatedVersion,
      });
    });
  });
}
