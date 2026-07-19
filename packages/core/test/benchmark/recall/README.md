# Recall benchmark corpus — intentionally vulnerable test fixtures

These files are **deliberately-vulnerable, deliberately-idiomatic crypto samples**
used to measure qScan's false-negative recall. They are the *bait* the scanner is
tested against, one subdirectory per supported language. See
[docs/validation/recall-benchmark.md](../../../../../docs/validation/recall-benchmark.md)
and `packages/core/test/recall.test.ts`.

**None of this is a real dependency of the project.** The toolkit ships
**zero runtime dependencies** ([ADR-0001](../../../../../docs/adr/0001-zero-runtime-dependencies.md));
its only real dev deps are eslint / prettier / tsx / typescript. Nothing here is
ever installed, built, resolved, imported, or deployed — the files are read as
static text by the benchmark and by qScan's detectors, nothing more.

## Why the manifests pin known-vulnerable versions

Three files are package manifests with real, canonical filenames:

- `go/go.mod` — `golang.org/x/crypto`, `cloudflare/circl`, `golang-jwt/jwt`
- `java/pom.xml` — `bouncycastle` (bcprov/bcpkix), `jackson-databind`
- `python/requirements.txt` — `python-dotenv`, others

They pin **outdated, quantum-vulnerable (and, incidentally, CVE-bearing) versions on
purpose** — that is precisely what qScan's dependency/manifest detectors must flag.
They must keep their canonical filenames (`go.mod` / `pom.xml` / `requirements.txt`)
because qScan's manifest detector keys on those exact names; renaming them would
silently drop those detections and weaken the benchmark. Do **not** "fix" or bump
these versions — that would defeat the fixture.

## GitHub Dependabot alerts on these files

Because the manifests carry canonical filenames, GitHub's **dependency graph parses
them and Dependabot raises vulnerability alerts** against them. Those alerts are
**false-risk noise**: the versions are never installed or shipped, so there is no
exposure.

**Policy:** dismiss such alerts as **"Vulnerable code is not actually used"**
(`not_used`) with a note pointing at this README. They only originate from paths
under `packages/**/test/benchmark/` — if an alert ever names a manifest *outside*
a test-fixture path, that one is real and must be triaged, not dismissed.

Dismiss from the command line:

```bash
gh api "repos/quantakrypto/pqc-tools/dependabot/alerts?state=open&per_page=100" \
  --jq '.[] | select(.dependency.manifest_path | test("test/benchmark/")) | .number' |
while read -r n; do
  gh api -X PATCH "repos/quantakrypto/pqc-tools/dependabot/alerts/$n" \
    -f state=dismissed -f dismissed_reason=not_used \
    -f dismissed_comment="Intentional vulnerable crypto test fixture (recall benchmark); never installed/built/deployed. See packages/core/test/benchmark/recall/README.md."
done
```
