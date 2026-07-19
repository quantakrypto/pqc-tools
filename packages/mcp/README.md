# @quantakrypto/mcp

A **Model Context Protocol (MCP) server** that gives AI coding agents post-quantum
readiness superpowers. It scans code for classical (quantum-vulnerable) asymmetric
cryptography and recommends NIST post-quantum / hybrid migrations, all backed by
[`@quantakrypto/core`](../core).

- **Zero runtime dependencies.** The MCP / JSON-RPC 2.0 protocol is implemented
  from scratch on Node built-ins (`node:readline`, `node:http`, `node:process`).
  The only dependency is `@quantakrypto/core`.
- **Two transports.** A `stdio` transport (the `quantakrypto-mcp` bin) for local agents
  like Claude, and a hostable `http` transport for running quantakrypto as a remote
  service (see [HOSTING.md](./HOSTING.md)).
- **Transport-agnostic core.** All protocol logic lives in a pure, unit-tested
  `McpServer` class; transports only do I/O.

## Install / register with an MCP client

The published package exposes a `quantakrypto-mcp` binary that speaks MCP over stdio:

```bash
# Claude Code / Claude Desktop
claude mcp add quantakrypto npx @quantakrypto/mcp
```

Equivalently, in an MCP client config:

```json
{
  "mcpServers": {
    "quantakrypto": {
      "command": "npx",
      "args": ["@quantakrypto/mcp"]
    }
  }
}
```

The bin is `quantakrypto-mcp` (→ `dist/stdio.js`). You can also run it directly:

```bash
node dist/stdio.js
```

## Protocol

MCP **stdio transport** is newline-delimited JSON: exactly one JSON-RPC 2.0
message per line on stdin/stdout (this is *not* HTTP-style `Content-Length`
framing). Supported methods:

| Method | Notes |
| --- | --- |
| `initialize` | Replies with `protocolVersion`, `capabilities.tools.listChanged = false`, and `serverInfo { name: "quantakrypto", version }`. |
| `notifications/initialized` | Notification; no response. |
| `ping` | Replies `{}`. |
| `tools/list` | Lists all tools with JSON-Schema `inputSchema`. |
| `tools/call` | Runs a tool, returns `{ content: [...], isError? }`. |

Unknown methods return JSON-RPC error `-32601`; bad params return `-32602`;
unparseable input returns `-32700`; non-request objects return `-32600`.

## Tools

Each tool returns MCP content: `{ content: [{ type: "text", text }], isError? }`.

### `scan_path`

Scan a file or directory for quantum-vulnerable cryptography.

```json
{
  "type": "object",
  "properties": {
    "path":   { "type": "string", "description": "Path to scan." },
    "format": { "type": "string", "enum": ["summary", "json"] }
  },
  "required": ["path"]
}
```

Returns a readiness summary (or the raw `ScanResult` JSON when `format: "json"`).

### `inventory_crypto`

Produce a 0–100 readiness score plus counts by algorithm, category, and severity.

```json
{
  "type": "object",
  "properties": { "path": { "type": "string" } },
  "required": ["path"]
}
```

### `explain_finding`

Explain a finding and its remediation. Provide a `ruleId`, an `algorithm`, or both.

```json
{
  "type": "object",
  "properties": {
    "ruleId":    { "type": "string" },
    "algorithm": { "type": "string", "description": "RSA, ECDH, ECDSA, …" }
  }
}
```

### `suggest_hybrid`

Recommend a PQC / hybrid migration from an `algorithm` or free-text `context`.

```json
{
  "type": "object",
  "properties": {
    "algorithm": { "type": "string" },
    "context":   { "type": "string" }
  }
}
```

### `list_rules`

List the quantakrypto detector catalog (ids + descriptions). No input.

```json
{ "type": "object", "properties": {} }
```

### `generate_cbom`

Scan a path and emit a **CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)**
of the classical cryptographic assets found, for compliance / supply-chain
tooling. Reads the filesystem, so it is gated like `scan_path` over HTTP.

```json
{
  "type": "object",
  "properties": { "path": { "type": "string" } },
  "required": ["path"]
}
```

## Copilot tools — migrate through the engine

These let an AI coding agent do a PQC migration **through the deterministic
engine** ("the model proposes, the engine disposes"): the agent plans, edits,
and re-verifies against the same detectors the CLI uses, so nothing is claimed
fixed that the scanner still flags.

- **`plan_migration`** — scan a path and return a prioritized, phased plan
  (harvest-now-decrypt-later first, then signatures, then transport/certs), each
  group with its PQC target and locations. Reads the filesystem, so it is gated
  like `scan_path` over HTTP. `{ path }`.
- **`get_fix_examples`** — before/after migration code for a classical
  `algorithm` (or a finding's `ruleId`). No filesystem access.
- **`verify_fix`** — run the detectors over a `code` snippet (plus `language` or
  `filename`) and report any classical crypto that remains. The agent's
  fix-confirmation loop. No filesystem access.
- **`check_dependency`** — look a package `name` (+ `ecosystem`, default npm) up
  in the vulnerable-dependency database. No filesystem access.
- **`score_delta`** — readiness-score / HNDL change between two finding sets
  (`before`, `after` from `scan_path --format json`). No filesystem access.
- **`triage_findings`** — deterministic, offline, key-free. Emits a triage
  REQUEST bundle (rubric + verdict schema + per-finding metadata + fingerprints)
  for the host agent to reason over. It never calls a model. No filesystem access.
- **`apply_triage`** — deterministically attach the host agent's verdicts to
  their findings (matched by fingerprint) and re-sort by exposure. Never
  suppresses; malformed verdicts are ignored. No filesystem access.
- **`remediate_findings`** — deterministic, offline, key-free. Emits a fix
  REQUEST bundle (rubric + fix schema + per-finding metadata + fingerprints) for
  the host agent to fix: propose the corrected file, verify with `verify_fix`,
  keep only verified fixes. Never merges. No filesystem access.

> Triage on the MCP plane keeps the "engine disposes" guarantee: the server
> stays offline and never holds an API key — the host agent (which already has
> the code open) does the reasoning, and `apply_triage` records it
> deterministically. The BYOK client that calls a provider directly lives only
> in `qscan --triage` (for CI, where there is no host agent).

## Resources & prompts

Beyond tools, the server exposes MCP **resources** and a **prompt** (advertised in
the `initialize` capabilities, all offline/static):

- `resources/list` + `resources/read` — `quantakrypto://rules` (the full rule
  catalog as JSON) and `quantakrypto://guide/migration` (a Markdown migration guide).
- `prompts/list` + `prompts/get` — the `migrate` prompt (optional `path` arg): a
  ready-made "scan → triage → remediate → verify, draft PR only" workflow.

## Hosted HTTP server (safe-by-default)

The same `McpServer` can be served over HTTP (a Streamable-HTTP-style JSON-RPC
endpoint) for remote deployments. The stdio transport trusts the local user and
is fully featured; the **HTTP transport is hardened**, because a hosted endpoint
is reachable by untrusted peers:

- **Binds to `127.0.0.1` by default** (not `0.0.0.0`). Override via
  `QUANTAKRYPTO_MCP_HOST`. Binding to a non-loopback host **without a token is refused
  at startup** (it would be an open, unauthenticated tool relay).
- **Bearer-token auth.** Set `QUANTAKRYPTO_MCP_TOKEN` and every `/mcp` request must
  send `Authorization: Bearer <token>`, else `401`. With no token set, only the
  loopback bind is allowed.
- **Filesystem tools are disabled by default.** `scan_path`, `inventory_crypto`,
  `generate_cbom` and `plan_migration` read arbitrary server paths, so over HTTP
  they are exposed only when `QUANTAKRYPTO_MCP_ALLOW_FS=1`. The knowledge /
  copilot tools that take no path (`explain_finding`, `suggest_hybrid`,
  `list_rules`, `get_fix_examples`, `verify_fix`, `check_dependency`,
  `score_delta`, `triage_findings`, `apply_triage`, `remediate_findings`) are
  always available. `tools/list` and `tools/call` both reflect the gating.
- **The networked probe tool is disabled by default.** `probe_endpoint` (active
  TLS/SSH probing) is the only tool that opens a socket. Over HTTP it is exposed
  only when `QUANTAKRYPTO_MCP_ALLOW_NETWORK=1` — a hosted server should not probe
  arbitrary hosts. On the local stdio transport it is always available. It still
  requires the per-call ownership attestation (`i_own_this=true`) and refuses
  ranges/CIDRs regardless of transport.
- **Filesystem tools are root-confined.** Even with `QUANTAKRYPTO_MCP_ALLOW_FS=1`,
  every scanned path must resolve inside the `QUANTAKRYPTO_MCP_ROOT` allow-list
  (`:`-separated; the process CWD by default). `..` traversal and out-of-root
  absolute paths (e.g. `/etc/passwd`) are rejected — the server is not an
  arbitrary-file-read oracle.
- **Origin validation.** `POST /mcp` rejects a browser request whose `Origin`
  host is not loopback (or allow-listed via `QUANTAKRYPTO_MCP_ALLOW_ORIGIN`),
  defending the default no-token loopback config against DNS-rebinding /
  localhost-CSRF. Non-browser clients (no `Origin`) are unaffected.
- **Limits + work budgets.** A 1 MiB request-body cap (`413` only on the cap,
  `400` on a transport error), a per-request tool timeout that **aborts the
  underlying scan** (`QUANTAKRYPTO_MCP_TIMEOUT_MS`, default 30000 → `504`), a
  response-size cap (`QUANTAKRYPTO_MCP_MAX_RESPONSE_BYTES`, default 4 MiB), and
  per-scan work budgets (`QUANTAKRYPTO_MCP_MAX_FILES` / `QUANTAKRYPTO_MCP_MAX_BYTES`)
  so a single call cannot exhaust host resources.

| Env var | Default | Purpose |
| --- | --- | --- |
| `QUANTAKRYPTO_MCP_HOST` (or `HOST`) | `127.0.0.1` | Bind interface. Non-loopback requires a token. |
| `PORT` | `3000` | Listen port. |
| `QUANTAKRYPTO_MCP_TOKEN` | _(unset)_ | When set, requires `Authorization: Bearer <token>`. |
| `QUANTAKRYPTO_MCP_ALLOW_FS` | _(off)_ | `1`/`true` exposes the filesystem tools over HTTP. |
| `QUANTAKRYPTO_MCP_ALLOW_NETWORK` | _(off)_ | `1`/`true` exposes the networked `probe_endpoint` tool over HTTP. |
| `QUANTAKRYPTO_MCP_ROOT` | _(cwd)_ | `:`-separated allow-list of directories the FS tools may scan. |
| `QUANTAKRYPTO_MCP_ALLOW_ORIGIN` | _(loopback)_ | Comma-separated extra `Origin` hosts allowed on `/mcp`. |
| `QUANTAKRYPTO_MCP_TIMEOUT_MS` | `30000` | Per-request deadline; aborts the in-flight scan on timeout. |
| `QUANTAKRYPTO_MCP_MAX_RESPONSE_BYTES` | `4194304` | Response-body size cap. |
| `QUANTAKRYPTO_MCP_MAX_FILES` | `25000` (cap `250000`) | Max files a single scan may read. |
| `QUANTAKRYPTO_MCP_MAX_BYTES` | `268435456` (cap 2 GiB) | Max cumulative bytes a single scan may read. |

```bash
# Local, knowledge tools only (default safe posture)
node dist/http.js

# Local with the filesystem tools enabled
QUANTAKRYPTO_MCP_ALLOW_FS=1 node dist/http.js

# Reachable from the network: a token is mandatory
QUANTAKRYPTO_MCP_HOST=0.0.0.0 QUANTAKRYPTO_MCP_TOKEN="$(openssl rand -hex 32)" node dist/http.js
```

Endpoints:

- `POST /mcp` — one JSON-RPC 2.0 message; the JSON-RPC response is the
  `application/json` body. Notifications get `202` with no body. An
  `mcp-session-id` header is echoed or minted on each request.
- `GET /health` — liveness probe returning `{ "status": "ok" }` (no auth).

```bash
curl -s localhost:3000/health
curl -s localhost:3000/mcp \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer YOUR_TOKEN' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

See [HOSTING.md](./HOSTING.md) for the full production design (auth, multi-tenant
sessions, rate limiting, scaling). A sample request/response transcript lives in
[`examples/transcript.jsonl`](./examples/transcript.jsonl).

## Programmatic use

```ts
import { createQuantakryptoServer } from "@quantakrypto/mcp";

const server = createQuantakryptoServer();
const res = await server.handle({ jsonrpc: "2.0", id: 1, method: "tools/list" });
```

## Development

```bash
npm run build   # tsc -b
npm test        # node --import tsx --test test/*.test.ts
```

Tests drive `McpServer.handle` directly (and the stdio loop via in-memory
streams) — no process spawning.

## License

Apache-2.0

## Support & training

Questions, commercial support, or post-quantum readiness training for your team —
visit **[quantakrypto.com](https://quantakrypto.com)** or email
**[hello@quantakrypto.com](mailto:hello@quantakrypto.com)**.
