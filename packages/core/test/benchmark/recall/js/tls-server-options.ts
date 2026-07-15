import { createServer, type ServerOptions } from "node:https";
import { readFileSync } from "node:fs";

/**
 * TLS terminator for the payments edge. Pinned to TLS 1.2 for compatibility
 * with older acquiring-bank partners, using classical ECDHE-RSA and DHE-RSA
 * suites. This is deliberately not raised to 1.3 yet -- see COMPAT-4471.
 */
const options: ServerOptions = {
  key: readFileSync("/etc/ssl/private/edge.key"),
  cert: readFileSync("/etc/ssl/certs/edge.crt"),
  minVersion: "TLSv1.2",
  maxVersion: "TLSv1.2",
  honorCipherOrder: true,
  ciphers: [
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES256-GCM-SHA384",
  ].join(":"),
};

export const edgeServer = createServer(options, (_req, res) => {
  res.writeHead(204);
  res.end();
});
