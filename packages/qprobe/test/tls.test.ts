import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type AddressInfo, type Socket } from "node:net";

import { probeHybridSupport } from "../src/tls.js";

/**
 * Spin up a localhost TCP server that runs `onConnect` for each connection, tracking
 * the sockets so the test can tear them down deterministically (the probe destroys
 * its own end; the server end must be destroyed here so cleanup doesn't hang).
 */
async function withServer(
  onConnect: (sock: Socket) => void,
  body: (port: number) => Promise<void>,
): Promise<void> {
  const conns = new Set<Socket>();
  const server = createServer((sock) => {
    conns.add(sock);
    sock.on("error", () => {}); // the probe resets the connection; ignore it
    sock.on("close", () => conns.delete(sock));
    onConnect(sock);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  try {
    await body((server.address() as AddressInfo).port);
  } finally {
    for (const s of conns) s.destroy();
    server.close();
  }
}

/**
 * A hostile or broken TLS endpoint must not crash the prober.
 *
 * A ServerHello record whose declared handshake length matches the bytes present,
 * but whose body is too short to hold the fixed fields (it can't fit the 32-byte
 * random), trips the parser's bounds check with a RangeError. That throw fires
 * inside the socket `data` handler; before the guard it escaped as an *uncaught
 * exception* and killed the process, leaving the probe promise pending forever.
 * Without the guard, node:test surfaces the uncaught RangeError and this fails.
 */
test("probeHybridSupport survives a malformed ServerHello without crashing", async () => {
  // ServerHello (handshake type 0x02) with declared length 5 but only 5 body bytes.
  const frag = Buffer.from([0x02, 0x00, 0x00, 0x05, 0, 0, 0, 0, 0]);
  const record = Buffer.concat([Buffer.from([0x16, 0x03, 0x03, 0x00, frag.length]), frag]);

  await withServer(
    (sock) => sock.write(record),
    async (port) => {
      const result = await probeHybridSupport("127.0.0.1", port, { timeoutMs: 2000 });
      assert.equal(result.hybridSelected, false);
      assert.equal(result.error, "malformed ServerHello");
    },
  );
});

/**
 * An endpoint that dribbles a few non-ServerHello bytes and stalls must resolve on
 * the timeout, not hang — the read-cap / timeout path stays intact alongside the
 * malformed-parse guard.
 */
test("probeHybridSupport resolves (does not hang) when no ServerHello arrives", async () => {
  await withServer(
    (sock) => sock.write(Buffer.from([0x16, 0x03, 0x03])),
    async (port) => {
      const result = await probeHybridSupport("127.0.0.1", port, { timeoutMs: 300 });
      assert.equal(result.hybridSelected, false);
      assert.ok(result.error, "expected an error (timeout / no ServerHello)");
    },
  );
});
