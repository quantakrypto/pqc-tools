/**
 * The networked half of the provenance check (`--audit`).
 *
 * `@quantakrypto/core`'s {@link checkProvenance} stays strictly offline (ADR-0005):
 * it parses the manifest and decides what to verify, but delegates the actual
 * HEAD request to an injected {@link RepoHeadRequester}. qScan is the plane
 * allowed to make outbound requests, so the `node:https`/`node:http`-backed
 * requester lives here. It NEVER rejects — every failure is mapped onto a
 * {@link RepoHeadOutcome} so core's logic stays branch-simple.
 */
import * as http from "node:http";
import * as https from "node:https";

import type { RepoHeadOutcome, RepoHeadRequester } from "@quantakrypto/core";

/**
 * Issue a HEAD request to `url` and classify the result:
 *  - a received HTTP response → `{ kind: "status", status }` (core treats 404/410
 *    as unresolved);
 *  - a DNS / host-not-found failure → `{ kind: "unresolved" }` (the declared
 *    repository host does not exist);
 *  - anything else (timeout, TLS, reset, bad URL) → `{ kind: "error" }`, which
 *    core skips silently. Redirects are not followed — a 3xx means the URL
 *    resolves, which is all provenance needs.
 */
export const repoHeadRequest: RepoHeadRequester = (url, timeoutMs) =>
  new Promise<RepoHeadOutcome>((resolve) => {
    let target: URL;
    try {
      target = new URL(url);
    } catch {
      resolve({ kind: "error", message: "invalid URL" });
      return;
    }
    if (target.protocol !== "http:" && target.protocol !== "https:") {
      resolve({ kind: "error", message: `unsupported protocol ${target.protocol}` });
      return;
    }
    const mod = target.protocol === "http:" ? http : https;
    const req = mod.request(
      target,
      { method: "HEAD", timeout: timeoutMs, headers: { "user-agent": "qscan-provenance" } },
      (res) => {
        res.resume(); // drain and free the socket.
        resolve({ kind: "status", status: res.statusCode ?? 0 });
      },
    );
    req.on("timeout", () => req.destroy(new Error("request timed out")));
    req.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "ENOTFOUND" || err.code === "EAI_FAIL") {
        resolve({ kind: "unresolved" });
      } else {
        resolve({ kind: "error", message: err.message });
      }
    });
    req.end();
  });
