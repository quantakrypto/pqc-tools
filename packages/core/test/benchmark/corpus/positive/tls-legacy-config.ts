// Positive: legacy/insecure TLS configuration object.
// Expected: tls-legacy-version + tls-reject-unauthorized.
import https from "node:https";

export const agent = new https.Agent({
  minVersion: "TLSv1",
  rejectUnauthorized: false,
});
