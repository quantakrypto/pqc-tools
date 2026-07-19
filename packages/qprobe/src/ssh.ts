/**
 * SSH endpoint inspection. An SSH server sends its identification banner and then
 * a cleartext SSH_MSG_KEXINIT (message 20) BEFORE any encryption or authentication
 * — so reading the offered key-exchange and host-key algorithm name-lists needs no
 * credentials and performs no crypto. We look for post-quantum KEX
 * (`sntrup761x25519-sha512@openssh.com`, `mlkem768x25519-sha256`) as a positive
 * readiness signal, and flag classical-only servers.
 *
 * The wire parsing (`parseKexinit`) is pure and unit-tested; `probeSsh` adds the
 * socket I/O.
 */
import { connect } from "node:net";

const SSH_MSG_KEXINIT = 20;

/** PQC / hybrid SSH key-exchange algorithm names (OpenSSH + drafts). */
export const PQ_SSH_KEX = [
  "sntrup761x25519-sha512@openssh.com",
  "sntrup761x25519-sha512",
  "mlkem768x25519-sha256",
  "mlkem768nistp256-sha256",
  "mlkem1024nistp384-sha384",
];

export interface KexInit {
  kexAlgorithms: string[];
  hostKeyAlgorithms: string[];
}

/** Read a `uint32`-length-prefixed comma-separated name-list at `off`. */
function readNameList(payload: Buffer, off: number): { list: string[]; next: number } {
  if (off + 4 > payload.length) throw new RangeError("truncated name-list length");
  const len = payload.readUInt32BE(off);
  const start = off + 4;
  if (start + len > payload.length) throw new RangeError("truncated name-list");
  const s = payload.subarray(start, start + len).toString("ascii");
  return { list: s === "" ? [] : s.split(","), next: start + len };
}

/**
 * Parse an SSH_MSG_KEXINIT payload (starting at the message-code byte) into its
 * kex and host-key algorithm name-lists.
 */
export function parseKexinit(payload: Buffer): KexInit {
  if (payload.length < 1 + 16 || payload[0] !== SSH_MSG_KEXINIT) {
    throw new RangeError("not an SSH_MSG_KEXINIT payload");
  }
  let off = 1 + 16; // message code + 16-byte cookie
  const kex = readNameList(payload, off);
  off = kex.next;
  const hostKey = readNameList(payload, off);
  return { kexAlgorithms: kex.list, hostKeyAlgorithms: hostKey.list };
}

/**
 * Extract the first binary SSH packet's payload from a raw server buffer that
 * begins after the identification banner line. Returns undefined if the packet is
 * not yet complete.
 */
export function extractPacketPayload(afterBanner: Buffer): Buffer | undefined {
  if (afterBanner.length < 5) return undefined;
  const packetLength = afterBanner.readUInt32BE(0);
  if (packetLength < 2 || packetLength > 1_000_000)
    throw new RangeError("implausible SSH packet length");
  if (afterBanner.length < 4 + packetLength) return undefined;
  const paddingLength = afterBanner[4];
  const payloadLen = packetLength - paddingLength - 1;
  if (payloadLen < 1) throw new RangeError("bad SSH padding");
  return afterBanner.subarray(5, 5 + payloadLen);
}

/** Locate the end of the SSH identification banner line (`SSH-...\n`). */
export function bannerEnd(buf: Buffer): number | undefined {
  // Servers may send pre-banner lines; find the SSH- line and its terminating LF.
  const idx = buf.indexOf("SSH-");
  if (idx < 0) return undefined;
  const lf = buf.indexOf(0x0a, idx);
  if (lf < 0) return undefined;
  return lf + 1;
}

export interface SshProbeResult {
  banner?: string;
  kex?: KexInit;
  pqKexOffered: boolean;
  error?: string;
}

/** Connect to an SSH endpoint and read its KEXINIT (no auth, no crypto). */
export function probeSsh(host: string, port: number, timeoutMs = 8000): Promise<SshProbeResult> {
  return new Promise((resolve) => {
    let buf = Buffer.alloc(0);
    let done = false;
    const finish = (r: SshProbeResult) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(r);
    };
    const socket = connect({ host, port });
    socket.setTimeout(timeoutMs);
    socket.on("connect", () => socket.write("SSH-2.0-qprobe_0.1\r\n"));
    socket.on("timeout", () => finish({ pqKexOffered: false, error: "timeout" }));
    socket.on("error", (e) => finish({ pqKexOffered: false, error: e.message }));
    // A peer that accepts then cleanly closes (FIN) before a complete KEXINIT would
    // otherwise leave the Promise unsettled (the timeout timer does not fire after a
    // clean close). The `done` guard makes this a no-op once we've already resolved.
    socket.on("close", () => finish({ pqKexOffered: false, error: "connection closed" }));
    socket.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > 512 * 1024) {
        finish({ pqKexOffered: false, error: "response too large" });
        return;
      }
      const end = bannerEnd(buf);
      if (end === undefined) return;
      const banner = buf.subarray(0, end).toString("ascii").trim();
      try {
        const payload = extractPacketPayload(buf.subarray(end));
        if (!payload) return; // wait for more data
        const kex = parseKexinit(payload);
        const pqKexOffered = kex.kexAlgorithms.some((a) => PQ_SSH_KEX.includes(a));
        finish({ banner, kex, pqKexOffered });
      } catch (e) {
        finish({ banner, pqKexOffered: false, error: (e as Error).message });
      }
    });
  });
}
