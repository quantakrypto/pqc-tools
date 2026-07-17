/**
 * SMTP STARTTLS probing. Mail transport is "communication between things": an MTA
 * that upgrades to TLS via STARTTLS negotiates the same classical (EC)DHE key
 * exchange as any TLS endpoint, so the session protecting mail in transit is
 * harvest-now-decrypt-later exposed. We speak the minimal SMTP dialog
 * (banner → EHLO → STARTTLS), upgrade the socket to TLS, and reuse the same
 * negotiated-parameter inspection as the direct TLS probe.
 *
 * The reply-framing helpers are pure and unit-tested; the socket dialog adds I/O.
 */
import { connect as netConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { extractNegotiated, type TlsNegotiated } from "./tls.js";

/** True once `buf` contains a COMPLETE SMTP reply (last line is `NNN␠…`). */
export function smtpReplyComplete(buf: string): boolean {
  if (!/\n$/.test(buf)) return false;
  const lines = buf.replace(/\r?\n$/, "").split(/\r?\n/);
  const last = lines[lines.length - 1] ?? "";
  return /^\d{3} /.test(last); // a space (not '-') after the code = final line
}

/** True if an EHLO reply advertises the STARTTLS capability. */
export function smtpAdvertisesStartTls(ehlo: string): boolean {
  return /^\d{3}[- ]STARTTLS\b/im.test(ehlo);
}

/**
 * Probe an SMTP endpoint: dial, EHLO, STARTTLS, upgrade to TLS, and read the
 * negotiated parameters + certificate posture. Returns `{ error }` when the server
 * does not offer STARTTLS or the upgrade fails.
 */
export function probeSmtpStartTls(
  host: string,
  port: number,
  opts: { servername?: string; timeoutMs?: number } = {},
): Promise<TlsNegotiated> {
  const timeoutMs = opts.timeoutMs ?? 8000;
  return new Promise((resolve) => {
    let done = false;
    let buf = Buffer.alloc(0);
    let stage: "banner" | "ehlo" | "starttls" = "banner";
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
    socket.on("timeout", () => finish({ error: "timeout" }));
    socket.on("error", (e) => finish({ error: e.message }));
    socket.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > 128 * 1024) return finish({ error: "SMTP response too large" });
      const text = buf.toString("ascii");
      if (!smtpReplyComplete(text)) return;

      if (stage === "banner") {
        buf = Buffer.alloc(0);
        stage = "ehlo";
        socket.write("EHLO qprobe.local\r\n");
      } else if (stage === "ehlo") {
        if (!smtpAdvertisesStartTls(text)) return finish({ error: "STARTTLS not advertised" });
        buf = Buffer.alloc(0);
        stage = "starttls";
        socket.write("STARTTLS\r\n");
      } else {
        if (!/^220 /m.test(text)) return finish({ error: "STARTTLS refused" });
        socket.removeAllListeners("data");
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
      }
    });
  });
}
