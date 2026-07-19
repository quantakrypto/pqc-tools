/**
 * PostgreSQL SSLRequest probing. A Postgres server does not speak raw TLS on
 * connect — the client first sends an 8-byte SSLRequest and the server answers a
 * single byte: `S` (SSL available) or `N` (not). On `S` the same socket is upgraded
 * to TLS, whose classical (EC)DHE key exchange protects the database session in
 * transit and is harvest-now-decrypt-later exposed. We send the SSLRequest, and on
 * `S` upgrade and reuse the direct TLS probe's negotiated-parameter inspection.
 *
 * The request-frame builder is pure and unit-tested; the socket dialog adds I/O.
 */
import { connect as netConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { extractNegotiated, type TlsNegotiated } from "./tls.js";

/** The 8-byte libpq SSLRequest message: length(0x00000008) + code(80877103). */
export function sslRequestFrame(): Buffer {
  const b = Buffer.alloc(8);
  b.writeInt32BE(8, 0); // message length
  b.writeInt32BE(80877103, 4); // SSLRequest magic (0x04D2162F)
  return b;
}

/** Probe a PostgreSQL endpoint: send SSLRequest, and on `S` upgrade to TLS. */
export function probePostgresSsl(
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
      try {
        socket.destroy();
      } catch {
        /* already closed */
      }
      resolve(r);
    };
    const socket = netConnect({ host, port });
    socket.setTimeout(timeoutMs);
    socket.on("connect", () => socket.write(sslRequestFrame()));
    socket.on("timeout", () => finish({ error: "timeout" }));
    socket.on("error", (e) => finish({ error: e.message }));
    socket.on("close", () => finish({ error: "connection closed" }));
    socket.on("data", (chunk: Buffer) => {
      if (chunk.length < 1) return;
      const reply = String.fromCharCode(chunk[0]);
      if (reply === "N") return finish({ error: "server does not offer TLS (SSLRequest → N)" });
      if (reply !== "S") return finish({ error: `unexpected SSLRequest reply "${reply}"` });
      socket.removeAllListeners(); // the TLS socket now owns the connection; drop stale net listeners
      const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":");
      const tls = tlsConnect({
        socket,
        servername: opts.servername ?? (isIp ? undefined : host),
        rejectUnauthorized: false,
        minVersion: "TLSv1.2",
      });
      tls.setTimeout(timeoutMs);
      tls.on("timeout", () => finish({ error: "timeout" }));
      tls.on("error", (e) => finish({ error: e.message }));
      tls.on("secureConnect", () => {
        const negotiated = extractNegotiated(tls);
        if (done) return;
        done = true;
        try {
          tls.destroy();
        } catch {
          /* already closed */
        }
        resolve(negotiated);
      });
    });
  });
}
