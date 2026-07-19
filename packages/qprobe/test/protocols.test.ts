/**
 * Tests for the added probe protocols: mode resolution, the IMAP/POP3 STARTTLS
 * dialogs, the PostgreSQL SSLRequest frame, and the plaintext-phase dance /
 * error handling (mocked with a local net server — no TLS upgrade needed, that
 * path is shared with smtp.ts / tls.ts and covered there).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import type { AddressInfo } from "node:net";

import { resolveMode, IMAP_DIALOG, POP3_DIALOG, sslRequestFrame } from "../src/index.js";
import { probeLineStartTls } from "../src/starttls.js";
import { probePostgresSsl } from "../src/postgres.js";

test("resolveMode maps well-known ports (auto), honours explicit modes", () => {
  const m = (port: number) => resolveMode({ host: "h", port }, "auto");
  assert.equal(m(22), "ssh");
  assert.equal(m(587), "smtp");
  assert.equal(m(143), "imap");
  assert.equal(m(110), "pop3");
  assert.equal(m(5432), "postgres");
  assert.equal(m(443), "tls");
  assert.equal(m(853), "tls"); // DoT is direct TLS
  assert.equal(m(993), "tls"); // IMAPS is direct TLS
  assert.equal(resolveMode({ host: "h", port: 443 }, "imap"), "imap"); // explicit wins
});

test("IMAP/POP3 dialogs carry the right command + success matcher", () => {
  assert.match(IMAP_DIALOG.command, /STARTTLS/);
  assert.ok(IMAP_DIALOG.success.test("a1 OK Begin TLS negotiation\r\n"));
  assert.ok(!IMAP_DIALOG.success.test("a1 NO STARTTLS not supported\r\n"));
  assert.match(POP3_DIALOG.command, /STLS/);
  assert.ok(POP3_DIALOG.success.test("+OK Begin TLS\r\n"));
  assert.ok(!POP3_DIALOG.success.test("-ERR command not supported\r\n"));
});

test("sslRequestFrame is the 8-byte libpq SSLRequest (length 8, code 80877103)", () => {
  const f = sslRequestFrame();
  assert.equal(f.length, 8);
  assert.equal(f.readInt32BE(0), 8);
  assert.equal(f.readInt32BE(4), 80877103);
});

/** Start a one-shot mock net server; returns the port + a closer. */
function mockServer(onConn: (sock: import("node:net").Socket) => void): Promise<{
  port: number;
  close: () => void;
}> {
  return new Promise((resolve) => {
    const server: Server = createServer(onConn);
    server.listen(0, "127.0.0.1", () => {
      resolve({ port: (server.address() as AddressInfo).port, close: () => server.close() });
    });
  });
}

test("IMAP probe reports an error when STARTTLS is refused", async () => {
  const { port, close } = await mockServer((sock) => {
    sock.write("* OK IMAP4rev1 ready\r\n");
    sock.once("data", () => sock.write("a1 NO STARTTLS not available\r\n"));
  });
  try {
    const r = await probeLineStartTls("127.0.0.1", port, IMAP_DIALOG, { timeoutMs: 3000 });
    assert.match(r.error ?? "", /STARTTLS not offered/);
  } finally {
    close();
  }
});

test("PostgreSQL probe reports an error when the server answers N (no TLS)", async () => {
  const { port, close } = await mockServer((sock) => {
    sock.once("data", () => sock.write("N"));
  });
  try {
    const r = await probePostgresSsl("127.0.0.1", port, { timeoutMs: 3000 });
    assert.match(r.error ?? "", /does not offer TLS/);
  } finally {
    close();
  }
});

test("probes do not hang when the peer accepts then closes (close handler)", async () => {
  const { port, close } = await mockServer((sock) => sock.destroy());
  try {
    const r = await Promise.race([
      probePostgresSsl("127.0.0.1", port, { timeoutMs: 3000 }),
      new Promise<{ error: string }>((res) => setTimeout(() => res({ error: "HUNG" }), 2500)),
    ]);
    assert.notEqual(r.error, "HUNG", "probe settled (did not hang on a clean close)");
  } finally {
    close();
  }
});
