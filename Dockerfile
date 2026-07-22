# Container image for the quantakrypto pqc-tools MCP server.
#
# Purpose: lets MCP directories (e.g. Glama) and self-hosters run the server
# in a sandbox. Glama sends a JSON-RPC `initialize` + `tools/list` over stdio
# and expects a valid reply — this image starts the stdio transport, so that
# introspection succeeds out of the box.
#
# This installs the PUBLISHED package rather than building from source: the
# server is a small stdio wrapper with zero runtime deps, so a global install
# is the smallest reproducible artifact. Bump both pins on each release.
#
# Licensing: covered by the repo-wide Apache-2.0 declaration in REUSE.toml
# (path = "**"), so no per-file SPDX header is required here.

# Base image pinned by digest (node 22 LTS on alpine). Refresh the digest when
# bumping the base — see docs/SUPPLY-CHAIN.md for the pinning policy.
FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2

# Install the published MCP server globally, version-pinned for reproducibility.
RUN npm install -g @quantakrypto/mcp@0.5.0

# Run as the built-in unprivileged node user.
USER node

# stdio transport by default: the directory/host speaks JSON-RPC over
# stdin/stdout. (HTTP hosting is documented separately in packages/mcp/HOSTING.md.)
ENTRYPOINT ["quantakrypto-mcp"]
