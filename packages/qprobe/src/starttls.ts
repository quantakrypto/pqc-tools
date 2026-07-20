/**
 * Generic line-based STARTTLS probing for IMAP and POP3 — the mail-retrieval
 * cousins of SMTP. Both greet with a single status line, take a one-shot upgrade
 * command (`a1 STARTTLS` / `STLS`), and then speak TLS on the same socket, so the
 * post-upgrade key exchange is the same classical (EC)DHE surface as any TLS
 * endpoint (harvest-now-decrypt-later exposed). We speak the minimal dialog and
 * reuse the direct TLS probe's negotiated-parameter inspection.
 *
 * (SMTP has a capability-negotiation step (EHLO) and lives in smtp.ts. LDAP
 * StartTLS is a binary ASN.1 extended operation and is intentionally out of scope.)
 */
import { connect as netConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { extractNegotiated, type TlsNegotiated } from "./tls.js";

/** A one-shot line-based STARTTLS dialog: send `command`, expect `success`, upgrade. */
interface StartTlsDialog {
  /** The upgrade command to send after the server greeting. */
  command: string;
  /** Matches the server reply that grants the TLS upgrade. */
  success: RegExp;
}

/** IMAP (RFC 3501): `* OK` greeting → `a1 STARTTLS` → `a1 OK`. */
export const IMAP_DIALOG: StartTlsDialog = {
  command: "a1 STARTTLS\r\n",
  success: /^a1 OK/im,
};

/** POP3 (RFC 2595): `+OK` greeting → `STLS` → `+OK`. */
export const POP3_DIALOG: StartTlsDialog = {
  command: "STLS\r\n",
  success: /^\+OK/im,
};

/**
 * Probe a line-based STARTTLS endpoint (IMAP/POP3): read the greeting line, send
 * the upgrade command, and on a success reply upgrade to TLS and read the
 * negotiated parameters + certificate posture. Returns `{ error }` when the server
 * does not offer the upgrade or it fails.
 */
export function probeLineStartTls(
  host: string,
  port: number,
  dialog: StartTlsDialog,
  opts: { servername?: string; timeoutMs?: number } = {},
): Promise<TlsNegotiated> {
  const timeoutMs = opts.timeoutMs ?? 8000;
  return new Promise((resolve) => {
    let done = false;
    let buf = Buffer.alloc(0);
    let stage: "greeting" | "response" = "greeting";
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
    // Clean close during the plaintext phase would otherwise hang the Promise.
    socket.on("close", () => finish({ error: "connection closed" }));
    socket.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > 64 * 1024) return finish({ error: "response too large" });
      const text = buf.toString("ascii");
      if (!/\n/.test(text)) return; // wait for a complete line

      if (stage === "greeting") {
        buf = Buffer.alloc(0);
        stage = "response";
        socket.write(dialog.command);
        return;
      }
      // stage === "response"
      if (!dialog.success.test(text)) return finish({ error: "STARTTLS not offered" });
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
