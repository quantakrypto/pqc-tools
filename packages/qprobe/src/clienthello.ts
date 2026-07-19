/**
 * Minimal, hand-rolled TLS 1.3 ClientHello builder + ServerHello/HelloRetryRequest
 * parser — just enough to detect whether a server supports the post-quantum hybrid
 * key-exchange group X25519MLKEM768 (codepoint 0x11EC, RFC 9370 / draft-kwiatkowski
 * -tls-ecdhe-mlkem). Node's bundled OpenSSL does not offer this group, so it cannot
 * be detected through `node:tls`; we advertise it in a raw ClientHello and read the
 * group the server selects.
 *
 * We advertise `supported_groups = [X25519MLKEM768, x25519, …]` AND send a
 * WELL-FORMED X25519MLKEM768 key_share (`ML-KEM-768.ek (1184) || X25519.pk (32)`,
 * per draft-ietf-tls-ecdhe-mlkem) alongside an x25519 share. A supporting server
 * then selects 0x11EC DIRECTLY in its ServerHello (we read the selected group) —
 * this catches servers that support-but-don't-*prefer* the hybrid group, which the
 * older HelloRetryRequest-only inference missed. The ML-KEM ek is well-formed but
 * throwaway (see mlkem768.ts): qProbe never completes the handshake, so the ML-KEM
 * shared secret is neither computed nor needed. A server that does not support the
 * group falls back to our x25519 share (or answers with a HelloRetryRequest, which
 * the parser still reads).
 *
 * This module is byte manipulation over Buffers (the X25519 key and ML-KEM encoding
 * come from node:crypto / mlkem768.ts); the socket I/O lives in tls.ts. The pure
 * functions are unit-tested with crafted bytes.
 */
import { randomBytes, generateKeyPairSync } from "node:crypto";
import { wellFormedMlKem768Ek } from "./mlkem768.js";

/** A raw 32-byte X25519 public key (from node:crypto — a real, valid key). */
export function x25519RawPublic(): Buffer {
  const { publicKey } = generateKeyPairSync("x25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x?: string };
  return Buffer.from(jwk.x ?? "", "base64url");
}

// TLS constants.
export const GROUP_X25519 = 0x001d;
export const GROUP_X25519MLKEM768 = 0x11ec;
export const GROUP_SECP256R1 = 0x0017;
const TLS13_VERSION = 0x0304;

const HS_CLIENT_HELLO = 0x01;
const HS_SERVER_HELLO = 0x02;
const REC_HANDSHAKE = 0x16;

const EXT_SERVER_NAME = 0x0000;
const EXT_SUPPORTED_GROUPS = 0x000a;
const EXT_SIGNATURE_ALGORITHMS = 0x000d;
const EXT_SUPPORTED_VERSIONS = 0x002b;
const EXT_KEY_SHARE = 0x0033;

/** The special ServerHello.random that marks a HelloRetryRequest (RFC 8446 §4.1.3). */
const HRR_RANDOM = Buffer.from(
  "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c",
  "hex",
);

function u16(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n, 0);
  return b;
}

/** Prefix `body` with a length field of `bytes` width (1, 2, or 3 bytes). */
function withLen(bytes: 1 | 2 | 3, body: Buffer): Buffer {
  const len = Buffer.alloc(bytes);
  if (bytes === 1) len.writeUInt8(body.length, 0);
  else if (bytes === 2) len.writeUInt16BE(body.length, 0);
  else len.writeUIntBE(body.length, 0, 3);
  return Buffer.concat([len, body]);
}

/** Build a single extension (type + 2-byte-length body). */
function ext(type: number, body: Buffer): Buffer {
  return Buffer.concat([u16(type), withLen(2, body)]);
}

/**
 * Build a raw ClientHello TLS record advertising the hybrid group. `keyShareGroup`
 * is the group we actually send a key_share for (default x25519), while
 * `supportedGroups` is what we advertise (hybrid first).
 */
export function buildClientHello(opts: {
  serverName?: string;
  supportedGroups?: number[];
  keyShareGroup?: number;
}): Buffer {
  const supportedGroups = opts.supportedGroups ?? [
    GROUP_X25519MLKEM768,
    GROUP_X25519,
    GROUP_SECP256R1,
  ];
  const keyShareGroup = opts.keyShareGroup ?? GROUP_X25519;

  const extensions: Buffer[] = [];

  if (
    opts.serverName &&
    opts.serverName.length > 0 &&
    !/^\d+\.\d+\.\d+\.\d+$/.test(opts.serverName)
  ) {
    // server_name: ServerNameList { name_type(0=host_name), HostName }
    const name = Buffer.from(opts.serverName, "ascii");
    const entry = Buffer.concat([Buffer.from([0x00]), withLen(2, name)]);
    extensions.push(ext(EXT_SERVER_NAME, withLen(2, entry)));
  }

  // supported_versions: TLS 1.3 only.
  extensions.push(ext(EXT_SUPPORTED_VERSIONS, withLen(1, u16(TLS13_VERSION))));

  // supported_groups (named_group list).
  extensions.push(ext(EXT_SUPPORTED_GROUPS, withLen(2, Buffer.concat(supportedGroups.map(u16)))));

  // signature_algorithms (a standard modern set).
  const sigAlgs = [0x0403, 0x0804, 0x0807, 0x0401, 0x0805, 0x0806];
  extensions.push(ext(EXT_SIGNATURE_ALGORITHMS, withLen(2, Buffer.concat(sigAlgs.map(u16)))));

  // key_share: send a REAL X25519 public plus a WELL-FORMED X25519MLKEM768 hybrid
  // share, so a server that supports the hybrid group can select it DIRECTLY (not
  // only via a HelloRetryRequest). For X25519MLKEM768 the client share is
  // `ML-KEM-768.ek (1184) || X25519.pk (32)` (draft-ietf-tls-ecdhe-mlkem). We never
  // complete the handshake, so the ML-KEM secret is neither computed nor needed.
  void keyShareGroup; // retained for API compat; the share set is now fixed
  const x25519Pub = x25519RawPublic();
  const hybridShareVal = Buffer.concat([wellFormedMlKem768Ek(), x25519Pub]);
  const shareEntries = Buffer.concat([
    u16(GROUP_X25519MLKEM768),
    withLen(2, hybridShareVal),
    u16(GROUP_X25519),
    withLen(2, x25519Pub),
  ]);
  extensions.push(ext(EXT_KEY_SHARE, withLen(2, shareEntries)));

  const cipherSuites = Buffer.concat([u16(0x1301), u16(0x1302), u16(0x1303)]);

  const helloBody = Buffer.concat([
    u16(0x0303), // legacy_version TLS 1.2
    randomBytes(32), // random
    withLen(1, randomBytes(32)), // legacy_session_id (non-empty → "middlebox compat")
    withLen(2, cipherSuites), // cipher_suites
    withLen(1, Buffer.from([0x00])), // compression_methods: null
    withLen(2, Buffer.concat(extensions)), // extensions
  ]);

  const handshake = Buffer.concat([Buffer.from([HS_CLIENT_HELLO]), withLen(3, helloBody)]);
  // TLS record: handshake, legacy record version 0x0301.
  return Buffer.concat([Buffer.from([REC_HANDSHAKE]), u16(0x0301), withLen(2, handshake)]);
}

/** A parsed TLS record. */
export interface TlsRecord {
  type: number;
  fragment: Buffer;
}

/** Split a buffer into TLS records. Stops at the first truncated record. */
export function parseRecords(buf: Buffer): TlsRecord[] {
  const out: TlsRecord[] = [];
  let off = 0;
  while (off + 5 <= buf.length) {
    const type = buf[off];
    const len = buf.readUInt16BE(off + 3);
    if (off + 5 + len > buf.length) break;
    out.push({ type, fragment: buf.subarray(off + 5, off + 5 + len) });
    off += 5 + len;
  }
  return out;
}

/** The result of reading a ServerHello / HelloRetryRequest. */
export interface ServerHelloInfo {
  isHelloRetryRequest: boolean;
  /** Group named in the key_share extension (selected group), if present. */
  selectedGroup?: number;
  /** Negotiated version from supported_versions (0x0304 for TLS 1.3), if present. */
  negotiatedVersion?: number;
  cipherSuite?: number;
}

/**
 * Parse a ServerHello handshake message body (the bytes AFTER the 4-byte handshake
 * header) and extract the selected group + negotiated version. Handles both a
 * normal ServerHello (key_share carries group + key) and a HelloRetryRequest
 * (key_share carries just the selected group) — in both the first 2 bytes of the
 * key_share body are the group.
 */
export function parseServerHelloBody(body: Buffer): ServerHelloInfo {
  let off = 0;
  const need = (n: number) => {
    if (off + n > body.length) throw new RangeError("truncated ServerHello");
  };
  need(2);
  off += 2; // legacy_version
  need(32);
  const random = body.subarray(off, off + 32);
  off += 32;
  const isHRR = random.equals(HRR_RANDOM);
  need(1);
  const sidLen = body[off];
  off += 1;
  need(sidLen);
  off += sidLen; // legacy_session_id_echo
  need(2);
  const cipherSuite = body.readUInt16BE(off);
  off += 2;
  need(1);
  off += 1; // legacy_compression_method

  const info: ServerHelloInfo = { isHelloRetryRequest: isHRR, cipherSuite };
  if (off + 2 > body.length) return info; // no extensions
  const extTotal = body.readUInt16BE(off);
  off += 2;
  const extEnd = Math.min(off + extTotal, body.length);
  while (off + 4 <= extEnd) {
    const extType = body.readUInt16BE(off);
    const extLen = body.readUInt16BE(off + 2);
    const start = off + 4;
    if (start + extLen > body.length) break;
    const extBody = body.subarray(start, start + extLen);
    if (extType === EXT_KEY_SHARE && extBody.length >= 2) {
      info.selectedGroup = extBody.readUInt16BE(0);
    } else if (extType === EXT_SUPPORTED_VERSIONS && extBody.length >= 2) {
      info.negotiatedVersion = extBody.readUInt16BE(0);
    }
    off = start + extLen;
  }
  return info;
}

/** Read the first ServerHello/HRR out of a raw response buffer, if any. */
export function readServerHello(raw: Buffer): ServerHelloInfo | undefined {
  for (const rec of parseRecords(raw)) {
    if (rec.type !== REC_HANDSHAKE) continue;
    const f = rec.fragment;
    if (f.length < 4) continue;
    if (f[0] !== HS_SERVER_HELLO) continue;
    const len = f.readUIntBE(1, 3);
    if (4 + len > f.length) continue;
    return parseServerHelloBody(f.subarray(4, 4 + len));
  }
  return undefined;
}
