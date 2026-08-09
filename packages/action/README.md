# quantakrypto Action

**Fail CI when new quantum-vulnerable cryptography lands.**

A zero-dependency GitHub Action that runs [qScan](../qscan) over your repository,
writes a [SARIF](https://sarifweb.azurewebsites.net/) report you can upload to
GitHub code scanning, annotates every finding inline in the diff, and (optionally)
comments a summary on the pull request. With a **baseline**, only *new*
quantum-vulnerable crypto fails the build, so you can adopt it on a legacy
codebase without drowning in pre-existing findings.

It also runs the other two checks, selected with [`checks`](#running-more-than-a-scan):
**conformance** ([Sieve](../sieve), FIPS 203/204/205 against your own
implementation) and **probe** ([qProbe](../qprobe), a live TLS/SSH handshake
against an endpoint you own). `checks` defaults to `scan`, so a workflow that
never sets it behaves exactly as it always has.

## Quick start

```yaml
name: Quantum Readiness
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # required to upload SARIF to code scanning
  actions: read            # also required by upload-sarif (see note below)
  pull-requests: write     # only if you enable comment-pr

jobs:
  quantakrypto:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: quantakrypto — Quantum Readiness Scan
        id: quantakrypto
        uses: quantakrypto/pqc-tools/packages/action@v1
        with:
          path: "."
          severity-threshold: "high"
          fail-on-findings: "true"
          format: "sarif"
          output: "quantakrypto.sarif.json"
          # baseline: ".quantakrypto/baseline.json"   # optional
          comment-pr: "true"
          github-token: ${{ github.token }}

      # Upload to GitHub code scanning (Security tab). Runs even if the scan
      # failed. Needs actions: read above, and Advanced Security on a private
      # repo — see the note below.
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: ${{ steps.quantakrypto.outputs.sarif-file }}
```

> **The SARIF upload needs two things beyond this snippet.**
>
> `permissions:` must include **`actions: read`** as well as `security-events:
> write`. Without it the upload validates your file, adds fingerprints, and then
> fails with `Resource not accessible by integration`, which reads like a problem
> with the SARIF rather than a missing scope.
>
> And code scanning itself requires **GitHub Advanced Security on private
> repositories**. It is free and always on for public repos; on a private repo
> without it the upload refuses with `Advanced Security must be enabled for this
> repository`. If you do not have it, drop the upload step: the scan still writes
> a job summary and annotates the diff, which is where most of the value is. Add
> `continue-on-error: true` if you would rather leave the step in place so it
> starts working the day it is enabled.

A ready-to-copy workflow lives at
[`examples/quantum-readiness.yml`](examples/quantum-readiness.yml).

## Inputs

| Input | Default | Description |
|---|---|---|
| `checks` | `scan` | Which checks to run: any comma-separated subset of `scan` (qScan), `conformance` (Sieve) and `probe` (qProbe). Defaults to `scan`, which is what this action did before, so an existing workflow is unaffected. |
| `probe-target` | | Hostname of a TLS/SSH endpoint you own, e.g. `api.example.com` (or `host:22`). Required when `probe` is selected. |
| `i-own-this` | `false` | Attest that you are authorised to probe `probe-target`. Required when `probe` is selected; the action will not make this statement on your behalf. |
| `conformance-impl` | | Command that runs your ML-KEM/ML-DSA/SLH-DSA implementation, e.g. `node ./impl.js`. Required when `conformance` is selected. |
| `conformance-param` | `ml-kem-768` | Parameter set for the conformance battery. |
| `mode` | `scan` | `scan` writes a report and gates the build; `comment-plan` posts a deterministic PQC migration plan as a PR comment and **never** fails the build. |
| `path` | `.` | Directory (or file) to scan, relative to the repo root. |
| `ignore` | | Extra paths to exclude, comma- or newline-separated (the CLI's repeatable `--ignore`). Use it for content, fixtures or docs that *describe* cryptography without using it: they match the detectors and become findings you never wanted. A baseline is the wrong tool there, because it files them as known debt rather than as not-code. |
| `include` | | Restrict the scan to paths matching these patterns, comma- or newline-separated. Empty scans everything not excluded. |
| `severity-threshold` | `high` | Minimum severity that fails the build: `critical`, `high`, `medium`, `low`, `info`. Findings below this never fail. |
| `fail-on-findings` | `true` | When `true`, exit non-zero if any finding at/above the threshold remains. Set `false` to report only. |
| `format` | `sarif` | Report format written to `output`: `sarif` or `json`. |
| `output` | `quantakrypto.sarif.json` | Path of the report file to write (relative to the workspace). |
| `baseline` | _(none)_ | Path to a qScan baseline file (`{ version, fingerprints }`, as written by `qscan --write-baseline`). Findings whose fingerprint it lists are suppressed, so only **new** crypto fails. |
| `comment-pr` | `false` | When `true` (and a token + PR context exist), post a summary comment on the PR. Never fails the build. |
| `github-token` | _(none)_ | Token used to comment on the PR. Usually `${{ github.token }}`. |
| `redact-snippets` | `false` | When `true`, omit the matched source snippet from every finding in the written report. Snippets of sensitive findings (embedded key material) are **always** omitted regardless of this setting. |
| `mandate` | _(none)_ | Comma/space-separated compliance mandate ids to gate against (`cnsa-2.0`, `nist-ir-8547`). Deadline-aware: reports each prohibited finding with its clause + deadline, fails the build only once a disallow deadline has passed. Independent of `fail-on-findings`; empty disables the gate. |
| `lead-months` | _(none)_ | Fail early when a `mandate` disallow deadline is within this many months. |
| `fail-now` | `false` | When `true`, fail on any `mandate`-prohibited finding immediately, regardless of its deadline. |
| `policy` | _(none)_ | Path to an org crypto-policy JSON (workspace-relative). With `mandate`, families the policy permits/is transitioning are annotated and exempt from the early gate (`lead-months`/`fail-now`); a passed disallow deadline still fails. |

## Outputs

| Output | Description |
|---|---|
| `findings-count` | Number of findings at/above the threshold, after baseline. |
| `sarif-file` | Path of the report file that was written. |
| `readiness-score` | Post-quantum readiness score, 0 (worst) – 100 (no classical asymmetric crypto found). |

## Running more than a scan

`checks` takes any comma-separated subset of `scan`, `conformance` and `probe`,
so one step covers all seven combinations.

The checks are **independent**, which is worth being precise about: each writes
its own section of the job summary, and one failing does not take the others
down with it. The SARIF report, the outputs, and the [exit
behavior](#exit-behavior) below all come from `scan` alone. Conformance and probe
report their verdicts to the job summary (and, on a platform-triggered run, to
quantakrypto); a failing conformance battery or a weak endpoint does not fail
the job. A *misconfiguration* still does, as it does for the scan: a missing
`i-own-this`, an unknown check id, an unusable `conformance-impl`.

```yaml
      - uses: quantakrypto/pqc-tools/packages/action@v1
        with:
          checks: "scan,conformance,probe"

          # conformance (Sieve) — drives YOUR implementation over the stdin/stdout
          # JSON protocol, so the command must exist in this repository.
          conformance-impl: "node ./pqc/impl.js"
          conformance-param: "ml-kem-768"

          # probe (qProbe) — a benign, unauthenticated handshake against one
          # endpoint. `i-own-this` is your attestation and is REQUIRED; the action
          # will not make it for you, and qProbe refuses to run without it.
          probe-target: "api.example.com"
          i-own-this: "true"
```

Three things are worth knowing before you enable them:

- **`conformance` runs a command from your repository.** That is the whole point
  of a conformance harness, but it means the step executes repository code. On a
  `pull_request` from a fork, that code is the contributor's. Gate it
  accordingly, or run conformance only on `push`.
- **`i-own-this` is a legal statement, not a flag.** Active probing of endpoints
  you are not authorised to test may be unlawful. It lives in the committed
  workflow so it is attributable in `git blame`.
- **A conformance run that cannot start is a failure, not a clean sheet.** If
  `conformance-impl` does not resolve to a runnable command, every check in the
  battery fails identically. The action reports that as one "the harness never
  ran" finding rather than as hundreds of cryptographic defects.

## Reporting to the quantakrypto platform

When a repository is connected at [quantakrypto.com](https://quantakrypto.com),
the platform triggers this action with a `repository_dispatch` and the action
posts the result back. That is the **only** case in which it makes an outbound
request, and it is constrained on purpose:

- it runs only for a `repository_dispatch` event, never on `push`, `pull_request`
  or `workflow_dispatch`;
- the callback URL must be `https://quantakrypto.com`. Any other origin is
  refused, so a forged dispatch cannot redirect the callback (which carries a
  one-time token) to a host of the attacker's choosing;
- redirects are refused rather than followed, and the request times out;
- the token is registered as a secret with the runner, so it is masked in logs.

Nothing about your source leaves CI: the payload is the readiness score, the
finding list, and a one-line summary. You do not write any of this yourself.
Committing the generated workflow is the whole integration.

## Comment-only migration plan (`mode: comment-plan`)

Set `mode: comment-plan` to post a deterministic, prioritized PQC migration plan
as a pull-request comment instead of gating the build. This mode **never fails
the job** — it is advisory, useful for gradually adopting the tool on a legacy
codebase before you turn on `fail-on-findings`.

```yaml
      - name: quantakrypto — Migration plan comment
        uses: quantakrypto/pqc-tools/packages/action@v1
        with:
          mode: "comment-plan"
          path: "."
          comment-pr: "true"
          github-token: ${{ github.token }}
```

## Readiness badge

Show your post-quantum posture in your README. The badge is served from
`quantakrypto.com`, so embedding it is also a backlink.

**Static call-to-action** (zero setup):

```markdown
[![Post-quantum readiness](https://quantakrypto.com/badge)](https://quantakrypto.com/tools)
```

**With your score** — the number comes from the action's `readiness-score`
output; the badge colours itself (green ≥ 80, amber 50–79, red < 50):

```markdown
[![Post-quantum readiness](https://quantakrypto.com/badge?score=82)](https://quantakrypto.com/tools)
```

> The badge renders the score you pass it. It is **self-reported by your CI and
> not independently verified by quantakrypto** — treat it as a status shield, not
> an attestation.

**Keep the score current from CI** — add this step after the scan (requires
`permissions: contents: write`). It rewrites the `?score=` in your README on
`main` whenever the score changes:

```yaml
      - name: Update readiness badge
        if: github.ref == 'refs/heads/main'
        env:
          SCORE: ${{ steps.quantakrypto.outputs.readiness-score }}
        run: |
          sed -i -E "s#(quantakrypto\.com/badge\?score=)[0-9]+#\1${SCORE}#g" README.md
          if ! git diff --quiet README.md; then
            git config user.name  "quantakrypto-bot"
            git config user.email "bot@users.noreply.github.com"
            git commit -am "chore: post-quantum readiness ${SCORE}/100"
            git push
          fi
```

## Exit behavior

The action **exits 1** (failing the job) when **both** are true:

1. `fail-on-findings` is `true`, **and**
2. at least one finding at or above `severity-threshold` survives the baseline.

Otherwise it exits 0. In all cases it writes the report file, sets outputs, and
emits inline annotations. Configuration errors (bad inputs, scan failures) also
fail the job with an `::error::` annotation. Severity ordering, most to least
severe: `critical` > `high` > `medium` > `low` > `info`.

Inline annotations are emitted per finding: blocking severities (at/above the
threshold) as `::error::`, lower severities as `::warning::`/`::notice::`, each
anchored to the finding's file and line so they appear in the PR diff.

## How baselines work

The Action and the [`qscan`](../qscan) CLI share **one** baseline format and
**one** fingerprint, defined in [`@quantakrypto/core`](../core). A baseline is a small
versioned file — `{ "version": 1, "fingerprints": [ … ] }` — written by
`qscan --write-baseline`. The fingerprint is a stable SHA-256 of the finding's
rule id, file, and (whitespace-normalized) code snippet, *excluding line/column*
so that unrelated edits which merely shift code up or down a file don't resurface
old findings. Any finding whose fingerprint already appears in the baseline is
suppressed; only genuinely new quantum-vulnerable crypto can fail the build.

Because the format is shared, a baseline produced locally with the CLI is
honoured byte-for-byte by the Action in CI, and vice versa.

Typical adoption flow:

1. Run `qscan --write-baseline .quantakrypto/baseline.json` once on `main` and commit
   the baseline file.
2. Point `baseline:` at that file. From then on, pull requests fail only when
   they introduce **new** findings at/above the threshold.
3. Refresh the baseline whenever you remediate, by re-running `--write-baseline`
   and re-committing it.

## Design

- **One code path with the CLI** — the scan, report rendering, and baseline are
  not re-implemented here. The Action calls `runQscan` / `renderReport` from
  [`@quantakrypto/qscan`](../qscan) and the shared baseline
  (`fingerprintFinding` / `applyBaseline` / `loadBaseline`) from
  [`@quantakrypto/core`](../core), so the Action and the `qscan` CLI produce identical
  findings, reports, and baseline semantics. This module is just the
  GitHub-runner glue (inputs, outputs, annotations, PR comment, exit policy).
  The same holds for the other two checks: `conformance` calls
  [`@quantakrypto/sieve`](../sieve) and `probe` calls
  [`@quantakrypto/qprobe`](../qprobe), including qProbe's own target parser, so
  the ownership rule that gates the CLI is the one that gates the Action rather
  than a second copy of it here.
- **One place decides what a result means** — the payload the platform receives
  is built in [`src/platform.ts`](src/platform.ts), not in the user's workflow.
  It used to be `jq` inside every repository that installed us, which meant a bug
  in it could never be fixed for anyone who had already committed it. A
  conformance run whose implementation could not start was reported as ~35
  high-severity crypto defects; correcting the `jq` changed only what *new*
  repositories would generate. Here, it is fixed for everyone on their next run.
- **Output-injection hardened** — a finding's `file`/`message`/`ruleId` come from
  the *scanned* repo, so in a fork PR they are attacker-controlled. Two sinks the
  Action writes with a token are escaped accordingly:
  - the **PR-comment Markdown table** — every cell is escaped by `mdCell`
    ([`src/escape.ts`](src/escape.ts)): pipes (`\|`), backticks, CR/LF, and HTML
    (`&`, `<`, `>`) so a crafted filename cannot break the table or inject HTML;
  - the **`::error file=…,line=…::message` workflow command** — the message is
    `escapeData`-encoded (`%`, CR, LF → `%25`/`%0D`/`%0A`) and command properties
    are `escapeProperty`-encoded (additionally `,` → `%2C`, `:` → `%3A`) in
    [`src/io.ts`](src/io.ts), so an attacker-named file cannot break out of the
    command.
- **Zero runtime dependencies** — only `@quantakrypto/core` + `@quantakrypto/qscan` (and Node
  built-ins). The small slice of the GitHub Actions toolkit this action needs
  (input parsing, outputs, annotations, PR comments) is implemented directly in
  [`src/io.ts`](src/io.ts) and [`src/main.ts`](src/main.ts); no `@actions/core`
  or `@actions/github`.
- **Testable core** — input parsing, the threshold→exit decision, summary
  rendering, the escaping helpers, and the annotation wire format are pure
  functions, unit-tested with `node:test` (no real runner required).

## License

Apache-2.0

## Support & training

Questions, commercial support, or post-quantum readiness training for your team —
visit **[quantakrypto.com](https://quantakrypto.com)** or email
**[hello@quantakrypto.com](mailto:hello@quantakrypto.com)**.
