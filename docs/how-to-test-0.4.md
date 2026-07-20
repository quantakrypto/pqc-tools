# quantakrypto 0.4.x — How to test everything

A hands-on runbook to verify every feature shipped in 0.4.0 actually works, using
the **published** npm packages. Each section is copy-paste runnable and lists the
**expected result** so you can tell pass from fail.

- Requires **Node ≥ 20** (`node -v`).
- Anything marked **(BYOK)** needs an LLM API key; everything else is offline and
  deterministic and needs no key.

---

## 1. Set up a sample vulnerable project

Everything below runs against this throwaway project. Paste the whole block:

```bash
mkdir -p /tmp/qk-test/src && cd /tmp/qk-test

# Source with quantum-vulnerable + insecure crypto (multiple rules).
cat > src/keys.ts <<'EOF'
import crypto from "node:crypto";
export const kp = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
export const ecdh = crypto.createECDH("prime256v1");
EOF

# TLS config — these two findings are DETERMINISTICALLY fixable by qremediate.
cat > src/tls.ts <<'EOF'
import https from "node:https";
export const opts = { minVersion: "TLSv1.1", rejectUnauthorized: false };
export const agent = new https.Agent(opts);
EOF

# A direct vulnerable dependency in package.json.
cat > package.json <<'EOF'
{ "name": "qk-test", "version": "1.0.0", "dependencies": { "elliptic": "^6.5.4" } }
EOF

# A TRANSITIVE vulnerable dep that appears ONLY in the lockfile (not package.json).
cat > yarn.lock <<'EOF'
# yarn lockfile v1
node-forge@^1.3.1:
  version "1.3.1"
  resolved "https://registry.yarnpkg.com/node-forge/-/node-forge-1.3.1.tgz#abc"
EOF

echo "sample project ready in $(pwd)"
```

---

## 2. Core scanning — `qscan`

> Tip: prefix every command with `npx` to avoid a global install, e.g.
> `npx @quantakrypto/qscan .`. To install once: `npm i -g @quantakrypto/qscan`.

### 2.1 Basic scan (human report)

```bash
npx @quantakrypto/qscan .
```

**Expect:** a readiness score, a table of findings including `node-crypto-keygen`
(RSA), `node-crypto-ecdh`, `tls-legacy-version`, `tls-reject-unauthorized`, and a
dependency finding for `elliptic` **and** `node-forge` (the latter proves lockfile
parsing — see §3). Exit code `1` (findings at/above the `high` threshold).

Check the exit code:

```bash
npx @quantakrypto/qscan . ; echo "exit=$?"
```

**Expect:** `exit=1`.

### 2.2 Machine formats

```bash
npx @quantakrypto/qscan . --format json  | head -40
npx @quantakrypto/qscan . --format sarif | head -40
npx @quantakrypto/qscan . --cbom -o qk.cbom.json && head -30 qk.cbom.json
```

**Expect:** valid JSON / SARIF 2.1.0 / CycloneDX CBOM. The SARIF `rules[]` array
advertises the full catalog (not just fired rules); the JSON `findings[]` carries
`ruleId`, `severity`, `hndl`, `remediation`, `location`.

### 2.3 Scan cache (unchanged files reused)

```bash
npx @quantakrypto/qscan . --cache            # first run: builds .quantakrypto-cache.json
ls -la .quantakrypto-cache.json
npx @quantakrypto/qscan . --cache            # second run: reuses unchanged files
```

**Expect:** identical findings both runs; the cache file exists after run 1.

---

## 3. yarn.lock / pnpm-lock.yaml dependency scanning

The sample's `yarn.lock` pins `node-forge`, which is **not** in `package.json`.

```bash
npx @quantakrypto/qscan . --format json | grep -i node-forge
```

**Expect:** a `dep-vulnerable` finding for `node-forge` — proving a transitive dep
in the lockfile is caught. (Try the same with a `pnpm-lock.yaml` containing
`  /node-forge@1.3.1:` under a `packages:` key.)

---

## 4. Triage — `qscan --triage` (BYOK)

Triage **re-ranks by real-world exposure and never suppresses** a finding, and it
**never changes the exit code**.

### 4.1 Dry-run preflight — NO key needed

See exactly what would be sent to the provider (secrets are always redacted):

```bash
npx @quantakrypto/qscan . --triage --dry-run
```

**Expect:** the redacted payload per finding (metadata + a bounded snippet), and
**no network call**. Try `--context metadata` (no code at all) and `--context file`
to see the levels differ.

### 4.2 Live triage — needs a key

```bash
export ANTHROPIC_API_KEY=sk-ant-...        # or QK_LLM_API_KEY / OPENAI_API_KEY
npx @quantakrypto/qscan . --triage --format json | grep -A3 '"triage"'
```

**Expect:** each finding gains a `triage` block `{ exposureScore, priority,
rationale }`; the human report re-sorts by exposure. **The exit code is unchanged**
from §2.1 — confirm:

```bash
npx @quantakrypto/qscan . --triage ; echo "exit=$?"   # still exit=1
```

No key set? It prints a notice and returns findings unannotated (never errors).

Provider options: `--llm-provider openai-compatible --llm-model gpt-4o-mini`
(set `OPENAI_API_KEY`, or a custom endpoint via the env the client reads).

---

## 5. Remediation — `qremediate`

### 5.1 Deterministic fixes (diff) — NO key needed

The two TLS findings in `src/tls.ts` have deterministic codemods.

```bash
npx -p @quantakrypto/qscan qremediate . --mode diff
```

**Expect:** a unified diff turning `TLSv1.1` → `TLSv1.3` and
`rejectUnauthorized: false` → `true`, plus a summary line
`N finding(s), 1 verified fix(es), M not auto-fixable`. Nothing is written yet.

### 5.2 Apply and re-verify

```bash
npx -p @quantakrypto/qscan qremediate . --mode apply
cat src/tls.ts                                    # now shows TLSv1.3 / true
npx @quantakrypto/qscan . --format json | grep -c 'tls-legacy-version'   # → 0
```

**Expect:** `src/tls.ts` is rewritten; a re-scan shows the TLS findings **gone**
(they passed the `verify_fix` gate). RSA/ECDH/`elliptic` remain — no safe
deterministic fix exists, which is correct.

### 5.3 LLM-proposed fixes (BYOK)

For findings no codemod covers (RSA, ECDH), `--llm` asks the model for a corrected
file; every patch still passes patch-policy + `verify_fix`.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
npx -p @quantakrypto/qscan qremediate . --mode diff --llm
```

**Expect:** additional proposed diffs for RSA/ECDH. Files containing secrets are
skipped by design. **Draft-PR mode** (`--mode pr`, run inside a git repo with `gh`
authenticated) commits verified fixes to a new branch and opens a **draft** PR —
it never merges.

---

## 6. MCP server — `@quantakrypto/mcp`

The MCP server is **deterministic and offline** (no key). Two ways to test:

### 6.1 Raw stdio smoke test

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"resources/list"}' \
  '{"jsonrpc":"2.0","id":4,"method":"prompts/list"}' \
  | npx @quantakrypto/mcp
```

**Expect:** four JSON-RPC responses — an `initialize` handshake advertising
`tools`/`resources`/`prompts` capabilities; a `tools/list` of **14** tools
(incl. `triage_findings`, `apply_triage`, `remediate_findings`); a `resources/list`
with `quantakrypto://rules` + `quantakrypto://guide/migration`; a `prompts/list`
with `migrate`.

Read the rule catalog resource:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"quantakrypto://rules"}}' \
  | npx @quantakrypto/mcp
```

**Expect:** a `contents[0]` with the full rule catalog as JSON.

### 6.2 Wire it into Claude Code / Claude Desktop

Add to your MCP client config (e.g. `~/.claude.json` or Claude Desktop's config):

```json
{
  "mcpServers": {
    "quantakrypto": { "command": "npx", "args": ["@quantakrypto/mcp"] }
  }
}
```

**Expect:** the client lists the quantakrypto tools/resources/prompts. Ask it to
"scan /tmp/qk-test and triage the findings" — it drives `scan_path` →
`triage_findings` → `apply_triage`, with the reasoning done by the client's own
model (the server stays key-free).

---

## 7. The GitHub Action

In a repo, add a workflow (`.github/workflows/quantakrypto.yml`):

```yaml
name: quantakrypto
on: [pull_request]
permissions: { contents: read, security-events: write, pull-requests: write }
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # Gate the build + upload SARIF.
      - uses: quantakrypto/pqc-tools/packages/action@v1
        with:
          path: .
          severity-threshold: high
      # OR: post a deterministic migration plan (never fails the build).
      - uses: quantakrypto/pqc-tools/packages/action@v1
        with:
          mode: comment-plan
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

**Expect (scan mode):** inline annotations on findings, a SARIF upload to code
scanning, the build failing when new findings land at/above the threshold.
**Expect (comment-plan mode):** an HNDL-first migration plan posted as a PR
comment; the build is **not** failed.

---

## 8. Run the packages' own automated test suite

To confirm the whole toolset is internally healthy (the ~1063 tests that gate CI):

```bash
git clone https://github.com/quantakrypto/pqc-tools && cd pqc-tools
npm ci
npm run build && npm test && npm run lint && npm run format:check
```

**Expect:** all six packages green, `# fail 0` throughout.

---

## 9. Quick pass/fail checklist

| Feature | Command | Pass looks like |
| --- | --- | --- |
| Core scan | `qscan .` | findings table, exit 1 |
| JSON/SARIF/CBOM | `qscan . --format json` | valid structured output |
| Scan cache | `qscan . --cache` (×2) | cache file, identical findings |
| Lockfile deps | `qscan . --format json \| grep node-forge` | a `dep-vulnerable` match |
| Triage preflight | `qscan . --triage --dry-run` | redacted payload, no network |
| Triage live (BYOK) | `qscan . --triage` | `triage` block, exit unchanged |
| Remediate diff | `qremediate . --mode diff` | TLS unified diff |
| Remediate apply | `qremediate . --mode apply` | file fixed, re-scan TLS-clean |
| Remediate LLM (BYOK) | `qremediate . --mode diff --llm` | proposed RSA/ECDH diffs |
| MCP tools/resources/prompts | stdio smoke test (§6.1) | 14 tools + resources + `migrate` |
| Action scan / comment-plan | PR workflow (§7) | annotations / plan comment |

## 10. Troubleshooting

- **`command not found: qscan`** — use `npx @quantakrypto/qscan .`, or
  `npm i -g @quantakrypto/qscan`.
- **`qremediate` not found via npx** — it's a second bin of the qscan package:
  `npx -p @quantakrypto/qscan qremediate …`.
- **`--triage` prints "needs an API key"** — set `ANTHROPIC_API_KEY`,
  `OPENAI_API_KEY`, or `QK_LLM_API_KEY`. Use `--dry-run` to test without a key.
- **`--mode pr` fails** — run inside a git repo with a remote and an authenticated
  `gh`; it opens a **draft** PR and never merges.
- **A brand-new install shows an old version** — `npm view @quantakrypto/qscan
  version` should read `0.4.1` or newer; clear the npx cache with `npx --yes`.
- **`qremediate` fixes only one of two TLS issues in a file** — that was a 0.4.0
  bug; ensure you're on **0.4.1+** (both `TLSv1.3` and `rejectUnauthorized: true`
  land in a single patch).
