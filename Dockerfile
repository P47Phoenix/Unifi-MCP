# syntax=docker/dockerfile:1.7

# UniFi MCP — container image.
#
# ## What this image is
#
# A **stdio** MCP server (ADR-01 in docs/prd.md). It speaks MCP over stdin and
# stdout and does NOT listen on a port. There is nothing to curl and nothing for
# an HTTP readiness probe to hit. Run it interactively:
#
#     docker run -i --rm -e UNIFI_API_KEY=... ghcr.io/p47phoenix/unifi-mcp:latest
#
# The `-i` is load-bearing: without an attached stdin the process has no
# transport and exits. A platform expecting a long-running listener will report
# this image as crash-looping, which is a symptom of the deployment shape, not
# of the image. See "Deploying this" in README.md.
#
# Use `--selftest` for a credential-free artifact check that exits 0/1.
#
# ## Build
#
# Targets linux/arm64 and linux/amd64. Node 20 matches package.json engines
# (>=18.17) and the CI matrix.

ARG NODE_VERSION=20.20.2

# ---------------------------------------------------------------------------
# Builder — full dependency tree, TypeScript compiled to dist/.
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION}-bookworm-slim AS builder

WORKDIR /build

COPY package.json package-lock.json ./

# `--omit=optional` deliberately excludes keytar. It is a native module that
# binds to an OS keychain (libsecret/D-Bus on Linux) that does not exist in a
# container, so building it here would add a compiler toolchain and produce a
# dependency that can only fail at runtime. The server already falls back to
# environment variables when the keychain is absent (FR-15) — which is the only
# credential path a container ever uses.
RUN npm ci --omit=optional --no-audit --no-fund

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Fail the build rather than ship an image whose dist/ is subtly wrong.
COPY specs ./specs
RUN node dist/index.js --selftest

# Reduce to production dependencies for the copy into the runtime stage.
RUN npm prune --omit=dev --omit=optional

# ---------------------------------------------------------------------------
# Runtime — no compiler, no dev dependencies, no npm install.
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION}-bookworm-slim AS runtime

# OCI labels; the workflow overwrites source/revision/created at build time.
LABEL org.opencontainers.image.title="unifi-mcp" \
      org.opencontainers.image.description="MCP server over the four published Ubiquiti UniFi developer APIs (Site Manager, Network, Protect, Mobility). Speaks MCP over stdio; does not listen on a port." \
      org.opencontainers.image.source="https://github.com/P47Phoenix/Unifi-MCP" \
      org.opencontainers.image.licenses="MIT"

ENV NODE_ENV=production

WORKDIR /app

COPY --from=builder /build/node_modules ./node_modules
COPY --from=builder /build/dist ./dist
COPY --from=builder /build/package.json ./package.json

# The server resolves specs/ relative to dist/.. and reads them at startup, so
# this layer is what makes NFR-17 hold — a full tool surface with no network.
COPY --from=builder /build/specs ./specs

# The upstream node image ships an unprivileged `node` user (uid 1000). Nothing
# here writes to disk: credentials come from the environment and never touch the
# filesystem (FR-15), so the whole tree can stay read-only.
USER node

# No port is exposed on purpose. Adding EXPOSE would imply a listener that does
# not exist and would mislead whoever deploys this.

# Checks the artifact, not the configuration: an image missing its specs/ layer
# fails, a correct image with no API key configured passes. The distinction
# matters because a probe that failed on a missing credential would report a
# broken image when the real problem is a missing secret.
HEALTHCHECK --interval=1m --timeout=15s --start-period=10s --retries=3 \
  CMD ["node", "dist/index.js", "--selftest"]

ENTRYPOINT ["node", "dist/index.js"]
