import { test } from "node:test";
import assert from "node:assert/strict";
import { parseKexinit, extractPacketPayload, bannerEnd, PQ_SSH_KEX } from "../src/ssh.js";

function nameList(s: string): Buffer {
  const b = Buffer.from(s, "ascii");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(b.length, 0);
  return Buffer.concat([len, b]);
}
function kexinitPayload(kex: string, hostkey: string): Buffer {
  return Buffer.concat([
    Buffer.from([20]), // SSH_MSG_KEXINIT
    Buffer.alloc(16, 0), // cookie
    nameList(kex),
    nameList(hostkey),
    nameList("chacha20-poly1305@openssh.com"), // encryption c2s (unused by parser)
  ]);
}
function wrapPacket(payload: Buffer): Buffer {
  const paddingLen = 4;
  const packetLength = payload.length + paddingLen + 1;
  const pl = Buffer.alloc(4);
  pl.writeUInt32BE(packetLength, 0);
  return Buffer.concat([pl, Buffer.from([paddingLen]), payload, Buffer.alloc(paddingLen, 0)]);
}

test("parseKexinit reads kex and host-key name-lists", () => {
  const p = kexinitPayload("curve25519-sha256,ecdh-sha2-nistp256", "ssh-ed25519,rsa-sha2-512");
  const k = parseKexinit(p);
  assert.deepEqual(k.kexAlgorithms, ["curve25519-sha256", "ecdh-sha2-nistp256"]);
  assert.deepEqual(k.hostKeyAlgorithms, ["ssh-ed25519", "rsa-sha2-512"]);
});

test("PQC KEX is recognised as a positive signal", () => {
  const p = kexinitPayload("sntrup761x25519-sha512@openssh.com,curve25519-sha256", "ssh-ed25519");
  const k = parseKexinit(p);
  assert.ok(k.kexAlgorithms.some((a) => PQ_SSH_KEX.includes(a)));
  // A classical-only server offers none of them.
  const classical = parseKexinit(kexinitPayload("curve25519-sha256", "ssh-ed25519"));
  assert.ok(!classical.kexAlgorithms.some((a) => PQ_SSH_KEX.includes(a)));
});

test("extractPacketPayload recovers the payload from a binary SSH packet", () => {
  const payload = kexinitPayload("curve25519-sha256", "ssh-ed25519");
  assert.deepEqual(extractPacketPayload(wrapPacket(payload)), payload);
  // A truncated buffer returns undefined (wait for more data), not a throw.
  assert.equal(extractPacketPayload(wrapPacket(payload).subarray(0, 6)), undefined);
});

test("bannerEnd locates the end of the SSH identification line", () => {
  const buf = Buffer.concat([
    Buffer.from("SSH-2.0-OpenSSH_9.6\r\n", "ascii"),
    Buffer.from([0x00, 0x01]),
  ]);
  const end = bannerEnd(buf);
  assert.equal(buf.subarray(0, end).toString("ascii").trim(), "SSH-2.0-OpenSSH_9.6");
});
