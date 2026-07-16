import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildClientHello,
  parseServerHelloBody,
  readServerHello,
  GROUP_X25519,
  GROUP_X25519MLKEM768,
} from "../src/clienthello.js";

function u16(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n, 0);
  return b;
}
function len2(body: Buffer): Buffer {
  return Buffer.concat([u16(body.length), body]);
}

const HRR_RANDOM = Buffer.from(
  "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c",
  "hex",
);

/** Craft a ServerHello handshake body selecting `group`, optionally as an HRR. */
function serverHelloBody(group: number, isHrr: boolean, withKeyExchange: boolean): Buffer {
  const random = isHrr ? HRR_RANDOM : Buffer.alloc(32, 0xab);
  const keyShareBody = withKeyExchange
    ? Buffer.concat([u16(group), len2(Buffer.alloc(32, 0x01))]) // group + key_exchange
    : u16(group); // HRR: selected_group only
  const extensions = Buffer.concat([
    Buffer.concat([u16(0x0033), len2(keyShareBody)]), // key_share
    Buffer.concat([u16(0x002b), len2(u16(0x0304))]), // supported_versions TLS 1.3
  ]);
  return Buffer.concat([
    u16(0x0303), // legacy_version
    random,
    Buffer.from([0x00]), // session_id len 0
    u16(0x1301), // cipher_suite
    Buffer.from([0x00]), // compression
    len2(extensions),
  ]);
}

test("HRR magic constant is exactly 32 bytes", () => {
  assert.equal(HRR_RANDOM.length, 32);
});

test("buildClientHello is a handshake record advertising the hybrid group", () => {
  const ch = buildClientHello({ serverName: "example.com" });
  assert.equal(ch[0], 0x16); // TLS handshake record
  assert.equal(ch[5], 0x01); // ClientHello
  // The hybrid group codepoint 0x11EC must appear (in supported_groups).
  assert.ok(ch.includes(Buffer.from([0x11, 0xec])));
});

test("parseServerHelloBody reads the selected group from a HelloRetryRequest", () => {
  const info = parseServerHelloBody(serverHelloBody(GROUP_X25519MLKEM768, true, false));
  assert.equal(info.isHelloRetryRequest, true);
  assert.equal(info.selectedGroup, GROUP_X25519MLKEM768);
  assert.equal(info.negotiatedVersion, 0x0304);
});

test("parseServerHelloBody reads the group from a normal ServerHello", () => {
  const info = parseServerHelloBody(serverHelloBody(GROUP_X25519, false, true));
  assert.equal(info.isHelloRetryRequest, false);
  assert.equal(info.selectedGroup, GROUP_X25519);
});

test("readServerHello unwraps a full TLS record + handshake header", () => {
  const body = serverHelloBody(GROUP_X25519MLKEM768, true, false);
  const handshake = Buffer.concat([
    Buffer.from([0x02]),
    Buffer.concat([Buffer.alloc(1), u16(body.length)]),
    body,
  ]);
  const record = Buffer.concat([Buffer.from([0x16]), u16(0x0303), len2(handshake)]);
  const info = readServerHello(record);
  assert.equal(info?.selectedGroup, GROUP_X25519MLKEM768);
});
