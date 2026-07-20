# Contributing to quantakrypto-tools

Thanks for helping make post-quantum readiness tooling better. This is an
Apache-2.0 project by [quantakrypto](https://quantakrypto.com); the methodology is open and
contributions are welcome.

## Principles (please read first)

1. **Zero runtime dependencies.** Every published package must run on Node
   built-ins alone. Dev-only tooling (TypeScript, `tsx`) is fine; a new runtime
   dependency needs a strong justification and a maintainer's sign-off.
2. **Simple, reusable, documented.** Prefer small pure functions, clear names,
   and a doc comment that says *why*. Shared logic belongs in `@quantakrypto/core`.
3. **Honesty over coverage.** Especially in `@quantakrypto/sieve`: never fabricate
   cryptographic test vectors. If we can't verify it correctly, we skip and say so.

## Getting started

Requires Node ≥ 20.

```bash
git clone git@github.com:quantakrypto/pqc-tools.git
cd quantakrypto-tools
npm install        # links the workspaces
npm run build      # tsc --build (project references)
npm test           # node:test across all packages
```

Source lives in `packages/*/src`; tests are `node:test` files in
`packages/*/test/*.test.ts` (run on `.ts` via `tsx`).

### Enable git hooks

A zero-dependency pre-commit hook lives in `.githooks/`. It runs the same gates
as CI (`build` → `lint` → `format:check` → `test`) so problems surface before
you push. Opt in once per clone:

```bash
git config core.hooksPath .githooks
```

On a fresh checkout the hook file may need the executable bit
(`chmod +x .githooks/pre-commit`). For a large, test-heavy commit you can gate
on only build + lint + format:check with `QUANTAKRYPTO_PRECOMMIT_FAST=1 git commit`,
or skip the hook entirely for a WIP checkpoint with `git commit --no-verify`.

## Conventions

- **TypeScript strict**, ESM, `module: NodeNext` — **relative imports must end
  in `.js`** (e.g. `import { scan } from "./scan.js"`), and use `import type` for
  type-only imports.
- The `@quantakrypto/core` public surface (`packages/core/src/index.ts` +
  `types.ts`) is a contract shared by every tool — coordinate changes to it.
- Add or update tests for any behaviour change. Add an example when you add a
  user-facing feature.
- Keep commit messages imperative and scoped (e.g. `core: add SSH-key detector`).

## Pull requests

1. Branch from `main`.
2. Ensure `npm run build` and `npm test` pass locally (CI runs them on Node 20 & 22).
3. Update the relevant package `README.md` and, if it changes a documented
   behaviour, `CHANGELOG.md`.
4. Describe what changed and why; link any related item in
   [`docs/OBJECTIVES.md`](docs/OBJECTIVES.md).

## Where to start

The toolchain's objectives, scope boundaries, and decisions are in
[`docs/OBJECTIVES.md`](docs/OBJECTIVES.md), and the architecture rationale in the
[ADRs](docs/adr/README.md). The detector line covers 14 source languages plus a
broad config/infra surface; good contribution areas are **new detection surfaces**
(a language or protocol pack), **growing the per-language recall corpus**, and
**test-coverage gaps**. New detectors follow the pattern in
[`packages/core/README.md`](packages/core/README.md) — a fast-reject gate, comment
masking, tight `\b`-anchored regexes, and positive/negative/gating tests.

## Security

Do not file security issues publicly — see [`SECURITY.md`](SECURITY.md).
