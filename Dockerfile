# syntax=docker/dockerfile:1.7

# UniFi MCP — container image.
#
# ## What this image is
#
# An MCP server (ADR-01 in docs/prd.md) that speaks one of two transports. The
# transport is chosen by configuration — the `UNIFI_MCP_TRANSPORT` environment
# variable — and never by the arguments you pass on the command line.
#
# The default is **stdio**: MCP over stdin and stdout, which is what you get if
# you set nothing. Run it interactively:
#
#     docker run -i --rm -e UNIFI_API_KEY=... ghcr.io/p47phoenix/unifi-mcp:latest
#
# The `-i` is load-bearing for that shape: without an attached stdin the process
# has no transport and exits. A platform expecting a long-running listener will
# report the stdio shape as crash-looping, which is a symptom of the deployment
# shape, not of the image. See "Deploying this" in README.md.
#
# Set `UNIFI_MCP_TRANSPORT=http` and the process serves MCP over
# streamable-HTTP instead, binding `UNIFI_HTTP_BIND`:`UNIFI_HTTP_PORT`. The
# default bind is loopback, which is unreachable from outside the container's
# network namespace — so a container deployment wants `UNIFI_HTTP_BIND=0.0.0.0`
# or nothing outside will ever reach it. `/healthz` and `/readyz` are the
# endpoints to point liveness and readiness probes at.
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
      org.opencontainers.image.description="MCP server over the four published Ubiquiti UniFi developer APIs (Site Manager, Network, Protect, Mobility). Speaks MCP over stdio by default, or streamable-HTTP when UNIFI_MCP_TRANSPORT=http." \
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

# EXPOSE is inert metadata and nothing more: it declares the port this image
# would use, it does not bind anything and it does not publish anything. The
# listener is opt-in — you get it only by setting `UNIFI_MCP_TRANSPORT=http`.
# The default is still stdio, and under stdio nothing ever binds this port.
# 8787 is here because it is the default value of `UNIFI_HTTP_PORT`.
EXPOSE 8787

# Checks the artifact, not the configuration: an image missing its specs/ layer
# fails, a correct image with no API key configured passes. The distinction
# matters because a probe that failed on a missing credential would report a
# broken image when the real problem is a missing secret.
HEALTHCHECK --interval=1m --timeout=15s --start-period=10s --retries=3 \
  CMD ["node", "dist/index.js", "--selftest"]

ENTRYPOINT ["node", "dist/index.js"]
