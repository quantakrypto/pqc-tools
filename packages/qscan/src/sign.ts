/**
 * Build an {@link EvidenceSigner} from an operator-provided shell command, for the
 * evidence attestation's detached signature / RFC-3161 timestamp (`--sign` /
 * `--timestamp`). Per ADR-0004 the tool implements NO cryptography: it pipes the
 * report's `contentHash` to the operator's own command (an `openssl` / `cosign`
 * invocation, a TSA client, …) on stdin and records that command's stdout verbatim.
 *
 * The command is run through the platform shell so it can pipe (`… | base64`). The
 * payload is passed on STDIN, never interpolated into the command string, so the
 * (tool-controlled) contentHash can't alter the (operator-controlled) command.
 */
import { spawnSync } from "node:child_process";

import type { EvidenceSigner } from "@quantakrypto/core";

const SIGN_TIMEOUT_MS = 30_000;
const SIGN_MAX_BUFFER = 1 << 20; // 1 MiB — a signature / timestamp token is small

/** Non-sensitive provenance label: the program name of the command (no args/paths). */
function signerLabel(command: string): string {
  // Skip any leading `KEY=value` env-assignment prefix (e.g. `AWS_SECRET=… cosign …`)
  // so a secret in it never lands in the recorded `signedWith`, then take the program.
  const prog =
    command
      .trim()
      .split(/\s+/)
      .find((t) => !/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) || "external-signer";
  return prog.replace(/^.*[/\\]/, ""); // basename, so a key path in args never leaks
}

/** An EvidenceSigner that shells out to `command`, piping the payload on stdin. */
export function commandSigner(command: string): EvidenceSigner {
  const label = signerLabel(command);
  return {
    label,
    sign(payload: string): string {
      const res = spawnSync(command, {
        shell: true,
        input: payload,
        encoding: "utf8",
        timeout: SIGN_TIMEOUT_MS,
        maxBuffer: SIGN_MAX_BUFFER,
      });
      // A command that exits before draining stdin makes spawnSync surface an EPIPE in
      // res.error even though the child ran and returned an exit status (seen on Linux,
      // not macOS). The exit status is the meaningful failure signal, so report a
      // non-zero exit (or a terminating signal) FIRST, and only treat res.error as
      // fatal when the child never produced a status (a real spawn failure, e.g. ENOENT).
      if (res.status !== null && res.status !== 0) {
        const detail = (res.stderr || "").trim().slice(0, 200);
        throw new Error(
          `--sign/--timestamp: command "${label}" exited ${res.status}${detail ? `: ${detail}` : ""}`,
        );
      }
      if (res.signal) {
        throw new Error(`--sign/--timestamp: command "${label}" terminated on ${res.signal}`);
      }
      if (res.error) {
        throw new Error(
          `--sign/--timestamp: command "${label}" failed to run: ${res.error.message}`,
        );
      }
      const out = (res.stdout || "").trim();
      if (!out) {
        throw new Error(`--sign/--timestamp: command "${label}" produced no output`);
      }
      return out;
    },
  };
}
