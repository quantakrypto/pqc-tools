/**
 * Ephemeral git worktree runner. Remediation applies candidate patches inside a
 * throwaway `git worktree` checked out at HEAD, so the user's working tree is
 * never touched while patches are being tried and verified. The worktree is
 * always removed afterwards, even if the callback throws.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const exec = promisify(execFile);

async function git(args: string[], cwd?: string): Promise<void> {
  await exec("git", args, { cwd });
}

/**
 * Create a detached worktree of `repoRoot` at HEAD, run `fn` with its path, and
 * always tear it down. Throws if `repoRoot` is not a git repository.
 */
export async function withWorktree<T>(
  repoRoot: string,
  fn: (dir: string) => Promise<T>,
): Promise<T> {
  try {
    await git(["rev-parse", "--is-inside-work-tree"], repoRoot);
  } catch {
    throw new Error(`withWorktree: "${repoRoot}" is not a git repository`);
  }
  const base = await mkdtemp(join(tmpdir(), "quantakrypto-wt-"));
  const dir = join(base, "wt");
  await git(["worktree", "add", "--detach", dir], repoRoot);
  try {
    return await fn(dir);
  } finally {
    try {
      await git(["worktree", "remove", "--force", dir], repoRoot);
    } catch {
      // best effort — the temp dir removal below still reclaims the disk.
    }
    await rm(base, { recursive: true, force: true });
  }
}
