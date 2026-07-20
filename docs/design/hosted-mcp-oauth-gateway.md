# Design: hosted, OAuth-gated multi-tenant quantakrypto MCP

Status: proposed · 2026-07-20 · owner: quantakrypto

Turn the shipped `@quantakrypto/mcp` HTTP transport (single static bearer token)
into a **hosted, multi-tenant service** that users reach by registering with an
email, and connect to with an OAuth 2.1 flow that issues **30-day** access
tokens. Serves **both** capability classes: advisory/knowledge tools and
content-based "accept-and-analyze" scanning.

## What already exists (do not rebuild)

- **Transport.** `packages/mcp/src/http.ts` — a hardened Streamable-HTTP JSON-RPC
  server: bearer auth (`authorizeRequest`), origin checks, body/response caps,
  per-request timeout, tool gating (`gateHttpTools`). Today it validates a single
  static `QUANTAKRYPTO_MCP_TOKEN`.
- **Tools (HTTP-safe today).** Advisory: `explain_finding`, `suggest_hybrid`,
  `list_rules`, `get_fix_examples`. Accept-and-analyze (content, not path):
  `verify_fix` (runs detectors over a submitted snippet), `check_dependency`,
  `triage_findings`, `remediate_findings`, `score_delta`. Path-based FS tools
  (`scan_path`, `inventory_crypto`, `generate_cbom`, `plan_migration`) and
  `probe_endpoint` stay **off** over HTTP — a hosted server has no user repo and
  must not read server paths or probe hosts.
- **Hosting notes.** `packages/mcp/HOSTING.md` §2 (sessions) and §3 (auth) already
  sketch the multi-tenant path this spec makes concrete.

## Architecture

Two roles, per the MCP Authorization spec (OAuth 2.1):

```
  MCP client ──(1) discover──►  Resource Server (/mcp)  ──► 401 + WWW-Authenticate,
             ◄─────────────────  RFC 9728 metadata ───────  points at the AS
             │
             ├─(2) OAuth 2.1 + PKCE ─► Authorization Server (auth.quantakrypto.com)
             │        email register/login (magic link) → consent → code → token
             │
             └─(3) POST /mcp  Authorization: Bearer <30-day access token>
                          RS validates JWT via AS JWKS, maps token → tenant,
                          enforces per-tenant rate limit + quota, serves tools
```

- **Resource Server = the MCP HTTP transport (this repo).** Extend `http.ts` auth
  from "compare one static token" to "validate an OAuth **access token**": verify
  the JWT signature against the AS JWKS, check `iss`/`aud`/`exp`, extract the
  subject (tenant) and scopes, then apply per-tenant rate limiting/quota. Tokens
  are 30-day JWTs so validation is offline (no per-request introspection call).
- **Authorization Server = a proven OAuth/OIDC product, self-hosted on "our
  server".** Do **not** hand-roll an OAuth 2.1 AS — it is security-critical and
  the MCP client ecosystem expects spec conformance (RFC 9728 protected-resource
  metadata, RFC 8414 AS metadata, RFC 7591 dynamic client registration, PKCE).
  Recommended default: **Ory Hydra** or **Keycloak** (both self-hostable, both
  support DCR + JWKS + email flows). The AS owns accounts, email verification
  (magic link), the consent screen, and 30-day token issuance.

### Why not a bespoke static-token endpoint?

The user picked full OAuth 2.1. Static per-user bearer tokens would be simpler but
(a) can't drive the one-click connector UIs some MCP hosts expect, and (b) put us
in the business of storing long-lived credentials. OAuth with short(er)-lived
JWTs + refresh, issued by a hardened AS, is the right posture for a hosted,
internet-reachable tool server.

## Data & tenancy

Owned by the AS (Hydra/Keycloak + its Postgres): accounts (email, verified_at),
OAuth clients (via DCR), grants, and refresh tokens. The RS is **stateless** —
it trusts the signed JWT. Optional RS-side store (Redis) only for rate-limit
counters and usage metering keyed by `sub`.

Token lifetime: **access token 30 days** (per the ask), refresh token longer;
revocation via the AS. A user dashboard (list/revoke active sessions, regenerate)
lives on the AS or a thin app in front of it.

## Rate limiting & abuse (a hosted MCP burns our compute)

Per-tenant token-bucket on `/mcp` (requests/min + monthly tool-call quota),
enforced in the RS keyed by `sub`. Email verification gates casual abuse; quotas
gate the rest. Keep the existing body/response/timeout caps.

## Website surface (this is built now, in quantakrypto-website)

- **`/docs`** — a docs hub orienting developers: the toolkit (qScan, MCP, Sieve,
  Action), the MCP connection guide, and links into the Standards & Guides
  clusters.
- **`/mcp`** — the MCP connection guide: what the server does, the tool catalog
  (advisory + analyze), the **local stdio** path available today
  (`npx @quantakrypto/mcp`), and the **hosted, email-gated OAuth** path
  (register → verify → connect) as early access. Config snippets per client.

## Build sequence

1. **Website `/docs` + `/mcp` pages** (this repo's sibling `quantakrypto-website`)
   — deployable immediately; documents local stdio now + hosted OAuth as early
   access. *(done first)*
2. **RS token validation** — extend `http.ts` to validate OAuth JWT access tokens
   (JWKS, iss/aud/exp, scopes) alongside the existing static-token mode; add
   per-tenant rate limiting. Pure, unit-tested like the current auth policy.
3. **AS deployment** — stand up Hydra/Keycloak on the server (Postgres + email
   provider + `auth.` subdomain + TLS), configure DCR, the email magic-link
   flow, the consent screen, and 30-day token TTL. *(ops; config + runbook in
   this repo, execution on the server)*
4. **Registration/dashboard** — the email sign-up + token/session management UI
   (AS-native theme, or a thin app in front).
5. **Cut `/mcp` docs over** from "early access" to live endpoint URL once (3)/(4)
   are deployed.

## What is ours vs. yours (infra)

Code I can write: the RS validation layer, the website pages, the AS
configuration + docker-compose + a deployment runbook, and the dashboard glue.
Yours to provide/run: the host, a Postgres instance, an email-sending provider
(magic links), the `auth.`/`mcp.` DNS + TLS, and the actual deploy.
