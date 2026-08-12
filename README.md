# UniFi MCP

An [MCP](https://modelcontextprotocol.io) server exposing all four published Ubiquiti UniFi
developer APIs — **Site Manager**, **Network**, **Protect**, and **Mobility** — as one
consistent tool surface, so you can ask about and operate your UniFi estate conversationally
instead of clicking through the console or hand-rolling `curl` against four APIs with three
pagination schemes and four error envelopes.

Requirements and rationale live in [`docs/prd.md`](docs/prd.md). Architecture decisions are
ADR-01 … ADR-04 in that document.

> **Status: pre-1.0, under construction.** The tool surface and configuration keys below are
> implemented against the vendored specs but have not yet been exercised end-to-end against a
> live console. Paths marked *unverified* below have been built from the published specs and
> fixtures only.
>
> The server speaks MCP over **stdio by default**. A **streamable-HTTP** serving transport is
> selected by configuration (`UNIFI_MCP_TRANSPORT=http`) for the single-tenant, self-hosted
> case — one instance, one operator's estate, behind your own TLS termination. See
> [Deploying this](#deploying-this).

## What it covers

| API | Spec version | Operations | Reachable via |
|---|---|---|---|
| Site Manager | `v1.0.0` | 14 | Cloud (`api.ui.com`) |
| Network | `v10.4.57` | 73 | Local-direct **or** Cloud Connector |
| Protect | `v7.1.87` | 73 | Local-direct **or** Cloud Connector |
| Mobility | `v1.0.0` | 8 | Cloud (`api.ui.com`) |

**168 operations total.** 163 are reachable; 5 are deliberately withheld and 2 further
request variants are withheld — see [Operations we do not ship](#operations-we-do-not-ship).

Coverage is a build gate, not a claim: `npm run coverage:check` enumerates every operation in
every vendored spec and fails if any is neither registered nor explicitly blocklisted with a
stated reason.

## The tool surface

168 operations is far past the ~30 at which one-tool-per-operation stops being viable — every
tool schema costs context on every turn. So the surface is a **hybrid** (ADR-02): five
high-traffic reads are promoted to dedicated tools, and the long tail sits behind search +
execute.

| Tool | Purpose |
|---|---|
| `unifi_list_consoles` | Consoles/hosts visible to your key, with firmware — the only source of the `consoleId` that Cloud Connector paths need |
| `unifi_list_sites` | Sites, with the identifiers most Network operations take as an argument |
| `unifi_list_devices` | Adopted network devices (APs, switches, gateways) for a site |
| `unifi_list_clients` | Clients currently connected to a site |
| `unifi_list_cameras` | Protect cameras |
| `unifi_search_actions` | Natural-language intent → matching action IDs and their schemas |
| `unifi_execute_action` | Run a **read-only** action by ID |
| `unifi_execute_write_action` | Run a **state-changing** action by ID — absent unless writes are enabled |

Read and write execution are separate tools deliberately: a single tool accepting both safe
and unsafe methods is auto-rejected at Anthropic directory review, and documenting the
difference inside one description does not satisfy the requirement.

Tools you do not need are not loaded. Disable Protect and you pay nothing for Protect schemas.

## Install

Requires Node.js ≥ 18.17.

```bash
git clone https://github.com/<you>/Unifi-MCP.git
cd Unifi-MCP
npm install
npm run build
```

Register it with Claude Code:

```bash
claude mcp add unifi -- node /absolute/path/to/Unifi-MCP/dist/index.js
```

An MCPB bundle — one file, no Node prerequisite — is the planned distribution format
(milestone M5 in the PRD). Until then this is the supported path.

## Container image

Published to GHCR on every push to `main`, built natively for **linux/arm64** and
**linux/amd64**:

```bash
docker run -i --rm \
  -e UNIFI_API_KEY=your-key \
  ghcr.io/p47phoenix/unifi-mcp@sha256:<digest>
```

**Pin by digest, not by `:latest`.** A mutable tag re-resolves on the next pull, so a
container restart or a node drain silently moves you to a different build, and when it
misbehaves there is no recorded previous version to go back to. Rolling back means
redeploying the previous digest. Resolve the current one with:

```bash
docker buildx imagetools inspect ghcr.io/p47phoenix/unifi-mcp:latest
```

As an MCP client entry:

```bash
claude mcp add unifi -- docker run -i --rm -e UNIFI_API_KEY=your-key ghcr.io/p47phoenix/unifi-mcp@sha256:<digest>
```

Verify any image without credentials:

```bash
docker run --rm ghcr.io/p47phoenix/unifi-mcp@sha256:<digest> --selftest
```

`--selftest` checks the *artifact* — that the vendored specs are present, the action
registry builds, and every promoted tool resolves to a backing action. It exits 0 on a
correct image with no API key configured, and non-zero on a broken one. That split is
deliberate: a probe that failed on a missing credential would report a broken image when
the real problem is a missing secret.

### Deploying this

**The image has two deployment shapes, and the configuration picks one.** With nothing set
it speaks MCP over stdio, which is the shape an MCP client spawns per session. Set
`UNIFI_MCP_TRANSPORT=http` and the same image binds a streamable-HTTP listener and runs as
an ordinary long-running service. `EXPOSE 8787` in the image is inert metadata: it binds
nothing, and it does not change the default transport.

Reference manifests for the HTTP shape are in this repository — [`deploy/kubernetes.yaml`](deploy/kubernetes.yaml)
and [`deploy/compose.yaml`](deploy/compose.yaml). Every number in them is derived from a
value documented here, and each derivation is named inline. Copy them rather than
reassembling the numbers by hand. Neither file contains a secret value — both deliver
credentials as mounted files.

#### The stdio shape

The `-i` in the `docker run` commands above is load-bearing — with no attached stdin the
process has no transport and exits immediately. Deployed as an ordinary long-running
workload it will look like a crash-loop, and that is the deployment shape being wrong
rather than the image. The supported pattern is for the **MCP client to spawn the
container** per session (`docker run -i --rm ...`), the same way it would spawn a local
process.

#### The HTTP shape

`UNIFI_MCP_TRANSPORT=http` inverts that. The process binds
`UNIFI_HTTP_BIND`:`UNIFI_HTTP_PORT`, serves MCP at `UNIFI_HTTP_PATH` (`/mcp`), and does not
exit when stdin closes — there is no `-i`, and a plain `docker run` or a Deployment is the
correct shape. `/healthz` and `/readyz` are real HTTP probe targets.

Every MCP request must present a **bearer secret** — `UNIFI_HTTP_TOKEN`, or better
`UNIFI_HTTP_TOKEN_FILE`, minimum 32 characters. That secret is not a UniFi credential; it is
what your MCP clients send to reach *this* server. Running without one requires typing
`UNIFI_HTTP_AUTH=none`, which is refused outright on any non-loopback bind. Rotation is
supported without an outage: add `UNIFI_HTTP_TOKEN_NEXT`, restart, move clients across,
remove the old one, restart.

**In a container, UNIFI_HTTP_BIND=0.0.0.0 — the loopback default cannot be reached by a probe.**
The default of `127.0.0.1` is loopback *inside the container's own network
namespace*: a kubelet, a Docker health check and a Service all live outside it and get
connection-refused. This is the single most common first-deployment failure and it presents
as a pod that never becomes ready.

Two more constraints sit next to that one, because all three are decided at the same moment:

- **`UNIFI_HTTP_ALLOWED_HOSTS` must contain the host name your clients actually send.** It
  is a DNS-rebinding control that protects browsers — **it is not an access control**, since
  the `Host` header is entirely caller-supplied and anyone can send any value. No
  `X-Forwarded-*` header is ever consulted, for host validation or for anything else. So a
  reverse proxy in front of this either preserves the original `Host`, or you put the
  address it forwards to in the allow-list. Most proxies rewrite `Host` to the upstream
  address by default (nginx `proxy_pass` without `proxy_set_header Host $host`), which
  produces a 403 on every request immediately after you finish fixing the bind address.
- **Routability is a deployment requirement, not a preference.** Local-direct Network and
  Protect calls go to your console's LAN address. A container in a cluster with no route to
  that network will advertise the full Network and Protect tool surface and then fail every
  call at connect time. Either the deployment can route to the console, or configure Cloud
  Connector instead. The server warns on stderr at startup, naming every configured local
  host, when the HTTP transport is selected with a non-loopback bind.

**The listener speaks plaintext HTTP and terminates no TLS.** Terminate it in front — an
ingress, a service mesh, or a reverse proxy — and do not publish this port directly. Without
that, the shared secret and every MCP request and response cross the network in the clear.
In-process TLS is deliberately out of scope.

**Restrict who can reach it.** The controls that bound this exposure are the shared secret
and network-layer policy. Neither the `Host` allow-list nor the secrecy of `UNIFI_HTTP_PATH`
is one. The unauthenticated surface — two probe endpoints and a uniform 401 — is a reliable
product fingerprint, and that is accepted only on the assumption that the listener is not
reachable from an untrusted population.

#### Shutdown, and the grace period your orchestrator must allow

On `SIGTERM` the process stops accepting new work, tells open sessions the server is going
away, lets in-flight calls finish, and exits. The budget for all of that is
`UNIFI_HTTP_SHUTDOWN_DEADLINE_MS`, default **35 000 ms — 35 seconds**.

**Set your orchestrator's grace period to at least 50 seconds for that default** —
`terminationGracePeriodSeconds: 50` on Kubernetes, `stop_grace_period: 50s` under Compose.
Kubernetes defaults to 30 and Docker to 10; either one `SIGKILL`s the process mid-drain,
which is the outcome the graceful path exists to prevent. If you raise the deadline, raise
the grace period with it — the 15-second gap is headroom, not slack.

Two probe endpoints, and the distinction matters:

- **`GET /healthz` is a *bind-liveness* check.** It answers `200 ok` for as long as the
  process is listening, in every phase including drain — a liveness probe that failed during
  shutdown would get the container killed part-way through it. Its limits are part of the
  contract: bind-liveness cannot fail for a process that is out of file descriptors, wedged
  on every session, or leaking toward OOM. Configure the liveness probe so that
  `failureThreshold × periodSeconds` exceeds the shutdown deadline.
- **`GET /readyz` reports readiness from process-local state only** — `starting` (503),
  `ready` (200), `draining` (503). It performs no outbound call, so a Ubiquiti outage does
  not take your instance out of service, and it never reports how many sessions are open.

`node dist/index.js --healthcheck` is the Docker-native health command: under
`UNIFI_MCP_TRANSPORT=http` it issues one local `GET /healthz`; otherwise it falls back to the
artifact self-test. Do not substitute `--selftest` in an HTTP deployment — it reports healthy
for a listener that never bound, and it forks a second Node interpreter that re-parses all
four OpenAPI specs inside the same memory limit.

#### Credentials in a container

The image runs as the unprivileged `node` user (uid 1000), writes nothing to disk, and needs
no writable volume. `keytar` is deliberately excluded from the image, so there is no OS
keychain path in a container at all.

**Prefer file delivery over environment variables.** Every secret the process holds — the
inbound shared secret, its rotation counterpart, and every UniFi API key — has a `*_FILE`
variable that names a path to read it from: `UNIFI_HTTP_TOKEN_FILE`,
`UNIFI_HTTP_TOKEN_NEXT_FILE`, `UNIFI_API_KEY_FILE`, `UNIFI_LOCAL_API_KEY_FILE`. Point them at
a Kubernetes Secret mounted as a volume (`secretKeyRef` for the *reference*; a projected
volume for the *value*) or a Compose `secrets:` entry. The reason is narrow and concrete:
`docker inspect` and `kubectl describe pod` both print literal environment values to anyone
who can run them, and a mounted file appears in neither.

Setting both `X` and `X_FILE` is a startup refusal naming both, not a silent precedence
rule — which of two secrets is live is not a question worth guessing at.

**The environment is empty on purpose after startup.** Once the secrets are read they are
deleted from `process.env`, so `docker exec <ctr> env` and `/proc/self/environ` show no
`UNIFI_HTTP_TOKEN` and no UniFi key. That is deliberate, and it is not evidence that the
variable never took effect. To confirm a secret was picked up, read the startup line and the
`auth=` and `reject_reason=` fields of the request log instead.

#### Reading the log

Everything operational goes to **stderr**, prefixed `unifi-mcp: `. There is no metrics
endpoint, no counters endpoint and no tracing exporter; parsing these lines is the whole of
the observability this product ships.

Each request produces one line with a fixed set of eight fields, always all eight:

```
unifi-mcp: req method=POST path=mcp status=200 dur_ms=143 auth=ok reject_reason=- writes=none client=10.42.0.7
```

| Field | Domain |
|---|---|
| `method` | `GET` `HEAD` `POST` `PUT` `PATCH` `DELETE` `OPTIONS` `OTHER` — a closed set, so a caller cannot inject a token of their choosing |
| `path` | `mcp` `healthz` `readyz` `other` — the **route label**, never the request target, which is attacker-controlled |
| `status` | the status actually sent |
| `dur_ms` | headers-parsed to response-headers-flushed; for a stream this is time to first byte, not stream lifetime |
| `auth` | `ok` or `rejected` |
| `reject_reason` | `-`, or one of `auth` `host` `origin` `path` `method` `body_size` `rate_limit` `session_limit` `draining` |
| `writes` | `none`, or the **effective** HTTP write set as a sorted comma-separated list. Never `all` |
| `client` | the peer address, IPv4-mapped addresses rendered as IPv4, no port, or `-` when unavailable |

Two things that are easy to misread:

- **`reject_reason=draining` is a rolling deploy, not a capacity incident.** It means the
  request arrived while the process was shutting down. `session_limit` is the capacity one.
- **Probe lines are rate-limited to one per route per 10 seconds** after the first. Without
  that, one unauthenticated source at high request rates buries the forensic record.

**Four rejection classes emit no line at all**, so an empty grep means *"this class does not
log"* rather than *"this did not happen"*: a `431` header-block overflow, a connection
refused by the connection cap, a connection closed for taking too long to send its headers,
and a connection refused during drain.

The client address is in the log, and **its retention is yours.** The product neither stores
nor forwards it; whatever your log pipeline keeps is what is kept. Startup diagnostics can
also carry enabled service names and configured local console addresses into that same
stream. No line ever carries the inbound secret, an `Authorization` header, a session
identifier, a request body or a tool result.

## Getting an API key

Create a key at [unifi.ui.com](https://unifi.ui.com) → **Settings → API Keys**, or on the
local console under **Integrations**. **The key is shown once at creation.**

For Mobility, the key additionally needs the `mobility` **app scope**, plus `read:mobility`
for reads and `write:mobility` for writes. Without the app scope every Mobility call returns
403. The caller must be a workspace Admin, and Mobility writes additionally require an active
cloud subscription on the target device.

**Site Manager keys are read-only today.** Ubiquiti's documentation states that when write
endpoints ship, **existing keys will not gain write access automatically — a manual key
update will be required.** This server therefore treats Site Manager as read-only and exposes
no Site Manager operation through the write tool.

## Configuration

The minimum viable configuration is **one API key**. With only `UNIFI_API_KEY` set, Site
Manager and Mobility work and you are asked for no host, no console ID, and no TLS decision.

Configuration is entirely by environment variable. **Any `UNIFI_*` variable this server does
not recognise is a fatal startup error, not a warning** — a typo cannot silently do nothing.
A malformed value is fatal too, and all problems are reported together in one pass rather
than one restart at a time.

### Reaching UniFi (outbound)

Nothing in this group changed with the HTTP serving transport.

**Credentials.** Every secret also has a `*_FILE` form that names a path to read it from,
which is the recommended delivery in a container — see
[Credentials in a container](#credentials-in-a-container). Setting both forms of the same
secret is a refusal.

| Variable | Default | Accepted values | Governed by | Purpose |
|---|---|---|---|---|
| `UNIFI_API_KEY` | *(unset)* | non-empty string | FR-14, FR-15 | Cloud key. Serves Site Manager, Mobility, and all Cloud Connector traffic. |
| `UNIFI_API_KEY_FILE` | *(unset)* | readable path, at most 4 KiB | FR-78, NFR-31 | Read the cloud key from a file instead of the environment. |
| `UNIFI_LOCAL_HOST` | *(unset)* | hostname or IP; a scheme and path are stripped | FR-08 | Console hostname/IP for local-direct Network and Protect. |
| `UNIFI_LOCAL_API_KEY` | *(unset)* | non-empty string | FR-14, FR-15 | Key bound to that console. |
| `UNIFI_LOCAL_API_KEY_FILE` | *(unset)* | readable path, at most 4 KiB | FR-78, NFR-31 | Read the default console's key from a file. |
| `UNIFI_LOCAL_HOST_<LABEL>` | *(unset)* | as `UNIFI_LOCAL_HOST` | FR-14 | An additional console. `<LABEL>` is used verbatim and pairs with the key of the same label; the unsuffixed pair is label `default`. |
| `UNIFI_LOCAL_API_KEY_<LABEL>` | *(unset)* | non-empty string | FR-14 | Key for the console labelled `<LABEL>`. |
| `UNIFI_LOCAL_API_KEY_<LABEL>_FILE` | *(unset)* | readable path, at most 4 KiB | FR-78, NFR-31 | Read that console's key from a file. |

**Choosing a route to the console.**

| Variable | Default | Accepted values | Governed by | Purpose |
|---|---|---|---|---|
| `UNIFI_CONSOLE_ID` | *(unset)* | non-empty string | FR-10, FR-53 | Console ID for Cloud Connector mode. Get it from `unifi_list_consoles`. Setting it flips the two transports below to `connector`. |
| `UNIFI_NETWORK_TRANSPORT` | `connector` when `UNIFI_CONSOLE_ID` is set, else `local` | `local`, `connector` | FR-11 | How this server reaches the **Network** API. |
| `UNIFI_PROTECT_TRANSPORT` | `connector` when `UNIFI_CONSOLE_ID` is set, else `local` | `local`, `connector` | FR-11 | How this server reaches the **Protect** API. |
| `UNIFI_LOCAL_CA_BUNDLE` | *(unset)* | path to a PEM bundle | FR-09, FR-54 | CA bundle that trusts your console's certificate. Mutually exclusive with the next row. |
| `UNIFI_LOCAL_TLS_INSECURE` | `false` | `1`/`true`/`yes`/`on`/`enabled`, or `0`/`false`/`no`/`off`/`disabled` | FR-09, NFR-14 | Explicit opt-in to skip certificate verification, for configured local hosts only. See below. |

**Which APIs are exposed, and whether they may write.**

| Variable | Default | Accepted values | Governed by | Purpose |
|---|---|---|---|---|
| `UNIFI_ENABLE_SITE_MANAGER` | derived from credentials | boolean, as above | FR-22 | Force Site Manager on or off, overriding credential-based auto-enablement in both directions. |
| `UNIFI_ENABLE_NETWORK` | derived from credentials | boolean | FR-22 | Force the Network API on or off. |
| `UNIFI_ENABLE_PROTECT` | derived from credentials | boolean | FR-22 | Force the Protect API on or off. |
| `UNIFI_ENABLE_MOBILITY` | derived from credentials | boolean | FR-22 | Force the Mobility API on or off. |
| `UNIFI_ENABLE_WRITES` | *(unset — no writes)* | comma-separated `site-manager`, `network`, `protect`, `mobility`, or `all` / `none` | FR-44, FR-45 | Services whose write operations to expose. Tokens apply left to right, so order matters; `all` adds only the services already enabled. Over HTTP this is narrowed again by `UNIFI_HTTP_ALLOW_WRITES`. |

Note that an empty value is not the same as an unset one for the boolean rows:
`UNIFI_ENABLE_NETWORK=` reads as **false**, not as "unset".

**Rate limits, retries and ceilings.** Defaults are the documented vendor limits where a
limit is published, and a conservative provisional value where it is not.

| Variable | Default | Accepted values | Governed by | Purpose |
|---|---|---|---|---|
| `UNIFI_RATE_LIMIT_CONNECTOR_PER_MIN` | `100` | positive integer | FR-12, NFR-15 | Requests per minute for Cloud Connector calls — the documented per-console limit. |
| `UNIFI_RATE_LIMIT_SITE_MANAGER_PER_MIN` | `10000` | positive integer | FR-26, NFR-15 | Requests per minute for Site Manager's stable `/v1/` paths. |
| `UNIFI_RATE_LIMIT_SITE_MANAGER_EA_PER_MIN` | `100` | positive integer | FR-30, NFR-15 | Separate, smaller bucket for Site Manager Early Access `/ea/` paths. **Dormant:** the vendored `v1.0.0` spec contains zero `/ea/` paths, so this bucket serves no operation today; it is retained so their return is a data change rather than a code change. |
| `UNIFI_RATE_LIMIT_MOBILITY_PER_MIN` | `100` | positive integer | FR-26, NFR-15 | Requests per minute for Mobility. Provisional — Ubiquiti publishes no limit. |
| `UNIFI_RATE_LIMIT_LOCAL_PER_MIN` | `100` | positive integer | FR-26, NFR-15 | Requests per minute for local-direct Network and Protect. Provisional — the console publishes no limit. |
| `UNIFI_RETRY_MAX_ATTEMPTS` | `3` | positive integer | FR-26 | Total attempts, including the first. Idempotent reads only; writes are never retried. |
| `UNIFI_RETRY_BASE_DELAY_MS` | `500` | positive integer | FR-26 | Base backoff delay. |
| `UNIFI_RETRY_MAX_DELAY_MS` | `8000` | positive integer | FR-26 | Ceiling on the backoff delay. |
| `UNIFI_RETRY_MAX_RETRY_AFTER_SECONDS` | `30` | positive integer | FR-26 | Largest `Retry-After` the client will honour; beyond it the error is surfaced instead. |
| `UNIFI_CONNECTOR_TIMEOUT_MS` | `25000` | positive integer | FR-12, NFR-16 | Per-attempt deadline after which an outbound call is abandoned. Raising it much past the default can exceed the shutdown budget; the server warns when it does. |
| `UNIFI_MAX_RESPONSE_BYTES` | `10485760` | positive integer | FR-12, NFR-16 | Responses larger than this are refused rather than buffered. |

> Two different words for "transport" live in this file. UNIFI_MCP_TRANSPORT is how clients reach this server. UNIFI_NETWORK_TRANSPORT is how this server reaches your console. They are unrelated and take different values.

### Being reached by MCP clients (inbound)

None of this applies to the stdio default. Every variable below is read only when
`UNIFI_MCP_TRANSPORT=http`.

**Selecting the transport.**

| Variable | Default | Accepted values | Governed by | Purpose |
|---|---|---|---|---|
| `UNIFI_MCP_TRANSPORT` | `stdio` | `stdio`, `http` | FR-62 | **How MCP clients reach this server.** Leave unset for the normal local/stdio shape; set to `http` to run as a standing network service. |
| `UNIFI_HTTP_BIND` | `127.0.0.1` | an IPv4 literal, an IPv6 literal, or `::` / `0.0.0.0` | FR-62, FR-73(b), FR-73(e) | Address the HTTP listener binds. Loopback by default; **a container needs `0.0.0.0` or its probes cannot reach it.** |
| `UNIFI_HTTP_PORT` | `8787` | `0` … `65535` | FR-63 | Port the HTTP listener binds. `0` picks an OS-assigned port, reported on stderr at startup. |
| `UNIFI_HTTP_PATH` | `/mcp` | an absolute path that does not normalise to `/healthz` or `/readyz` | FR-67, FR-73(d) | Path the MCP endpoint is served on. Must be absolute. The two probe paths are reserved and cannot be taken. |

> `UNIFI_HTTP_PORT=0` is not supported with `--healthcheck` or any container or Kubernetes health check: the health command runs as a separate process from the server, has no way to discover the OS-assigned port, and dials the configured `0` — so it fails silently every time. Give any orchestrated deployment a fixed port; `0` is for local runs and test harnesses, which read the real port from the serving line on stderr.

**Authenticating callers.**

| Variable | Default | Accepted values | Governed by | Purpose |
|---|---|---|---|---|
| `UNIFI_HTTP_AUTH` | `bearer` | `bearer`, `none` | FR-64, FR-73(a), FR-73(e) | Inbound authentication mode. `none` disables it entirely and is refused on any non-loopback bind. Any third value is refused. |
| `UNIFI_HTTP_TOKEN` | *(unset)* | a string of at least 32 characters | FR-64, FR-81 | **The shared secret MCP clients present to reach this server.** Not a UniFi credential — see the naming warning below. |
| `UNIFI_HTTP_TOKEN_FILE` | *(unset)* | readable path, at most 4 KiB | FR-78 | Read the inbound shared secret from a file instead of the environment. The documented path for containers and `secretKeyRef`. |
| `UNIFI_HTTP_TOKEN_NEXT` | *(unset)* | a second accepted secret, same 32-character floor | FR-64 | A second inbound secret accepted alongside the first, so rotation is add → restart → move clients → remove → restart. |
| `UNIFI_HTTP_TOKEN_NEXT_FILE` | *(unset)* | readable path, at most 4 KiB | FR-78 | File delivery for the rotation secret. |
| `UNIFI_HTTP_AUTH_FAIL_PER_MIN` | `20` | positive integer | FR-81 | Rejections allowed from one source per rolling minute before it is throttled. Counts every uniform-401 emission, not only authentication failures. |

**Browser-facing controls.**

| Variable | Default | Accepted values | Governed by | Purpose |
|---|---|---|---|---|
| `UNIFI_HTTP_ALLOWED_HOSTS` | *(empty)* | comma-separated host names or IP literals, matched port-agnostically | FR-65, FR-73(b) | Host names clients will use in the `Host` header. A DNS-rebinding control that protects browsers — **not** an access control. |

**Writes over HTTP.**

| Variable | Default | Accepted values | Governed by | Purpose |
|---|---|---|---|---|
| `UNIFI_HTTP_ALLOW_WRITES` | `none` | the same grammar as `UNIFI_ENABLE_WRITES`: `none`, `all`, or a comma-separated service list | FR-71, FR-73(c) | **Second, HTTP-only write gate.** Writes over HTTP need this *and* `UNIFI_ENABLE_WRITES`; the effective set is the intersection. Deliberately not a boolean — `true` and `false` are refused. |

**Limits and lifecycle.** Nobody sets these on a first deployment.

| Variable | Default | Accepted values | Governed by | Purpose |
|---|---|---|---|---|
| `UNIFI_HTTP_MAX_SESSIONS` | `32` | positive integer | FR-77, NFR-30 | Maximum concurrent MCP sessions. An `initialize` beyond it is refused. |
| `UNIFI_HTTP_SESSION_IDLE_TTL_MS` | `300000` | positive integer | FR-77, NFR-30 | Idle time after which an abandoned session is evicted and its identifier invalidated. |
| `UNIFI_HTTP_MAX_CONNECTIONS` | `64` | positive integer | FR-76, NFR-29 | Maximum concurrent TCP connections accepted, less a reserved headroom for probes. |
| `UNIFI_HTTP_MAX_BODY_BYTES` | `1048576` | positive integer | FR-76, NFR-29 | Maximum inbound request body. Larger bodies are refused without being buffered. |
| `UNIFI_HTTP_MAX_HEADER_BYTES` | `16384` | positive integer | FR-76, NFR-29 | Maximum inbound header block. **This is also the bound on pre-authentication hashing work** — it caps the bearer token an unauthenticated caller can make the server digest. Raising it raises per-request pre-auth CPU. |
| `UNIFI_HTTP_HEADERS_TIMEOUT_MS` | `10000` | positive integer | FR-76, NFR-29 | How long a caller may take to finish sending headers before the connection is closed. |
| `UNIFI_HTTP_REQUEST_TIMEOUT_MS` | `30000` | positive integer | FR-76, NFR-29 | How long an inbound request may take to arrive. Does **not** bound a long-lived stream. |
| `UNIFI_HTTP_KEEPALIVE_TIMEOUT_MS` | `5000` | positive integer | FR-76, NFR-29 | How long an idle keep-alive socket is held open. |
| `UNIFI_HTTP_SSE_KEEPALIVE_MS` | `15000` | positive integer | FR-70 | Interval between keep-alive frames on an open stream. |
| `UNIFI_HTTP_SHUTDOWN_DEADLINE_MS` | `35000` | positive integer | FR-70, NFR-27 | Graceful-shutdown budget on `SIGTERM`. **Set your orchestrator's grace period to at least 50 s for this default.** |

**Three names are easy to confuse, and each mistake has a different symptom:**

| Confused pair | Symptom |
|---|---|
| `UNIFI_HTTP_TOKEN` vs `UNIFI_API_KEY` / `UNIFI_LOCAL_API_KEY` | All three are "the secret", but two are UniFi's and one is ours. Putting the UniFi key in `UNIFI_HTTP_TOKEN` **401s every request**. The log line reads `auth=rejected reject_reason=auth`. |
| `UNIFI_MCP_TRANSPORT` vs `UNIFI_NETWORK_TRANSPORT` / `UNIFI_PROTECT_TRANSPORT` | Same noun, opposite direction; one takes `stdio`/`http`, the others `local`/`connector`. Either mistake is a startup refusal naming the variable and its valid values. |
| `UNIFI_HTTP_ALLOW_WRITES` vs `UNIFI_ENABLE_WRITES` | Same grammar, one word apart, and **both** must be set for HTTP writes to work. Setting only one leaves `unifi_execute_write_action` absent. The server prints an upper-case warning at startup when that is what happened, and every request log line carries the effective `writes=` set. |

### Where keys are read from

On desktop and MCPB installs, keys are read from the **OS keychain** first (via `keytar`) and
fall back to environment variables — or a `*_FILE` path — for headless and CI use. The server
never writes a key to disk. When it falls back to environment variables it says so on stderr.

`keytar` is an optional native dependency: if it fails to build, the server still runs on the
environment-variable path, and it is omitted from the container image entirely.

**The keychain lookup is bounded by a fixed 10-second timeout.** A locked or wedged keychain
daemon therefore surfaces as one failed call rather than a hang that precedes every outbound
request and every shutdown. On expiry the lookup is abandoned exactly as an unavailable
keychain already is: resolution falls through to the file and environment path, so an
operator who also supplies the key by variable or file sees no failure at all. A timed-out
lookup is not cached in either direction, so unlocking the keychain and retrying works
without restarting the server. The bound is deliberately not configurable — the remedy for a
genuinely slow keychain is file or environment delivery, not a longer timeout. **In a
container none of this applies**: `keytar` is absent, so there is no keychain path to bound.

### Reaching a controller on your LAN

Network and Protect live on your console, not in the cloud. Two ways to reach them, chosen by
configuration — the tool names and arguments are identical either way:

- **Local-direct** — `https://{host}/proxy/network/integration`. No rate limit, no proxy
  timeout, but the console presents a **self-signed certificate**.
- **Cloud Connector** — proxied through `api.ui.com`, so it works from anywhere with no VPN.
  Costs a documented **100 requests/minute per console**, a 25-second per-request timeout, and
  a 10 MB response cap. Needs console firmware ≥ 5.0.3.

Certificate verification is **on by default and stays on**. If your console presents a
self-signed certificate you get an error naming the problem and offering exactly two remedies:
point `UNIFI_LOCAL_CA_BUNDLE` at a bundle that trusts it, or set `UNIFI_LOCAL_TLS_INSECURE=1`.
The insecure opt-in applies **only** to configured local console hosts and never to
`api.ui.com` — that is enforced in code, not by convention. When it is active the server warns
on stderr naming the affected hosts.

## Safety posture

**Read-only by default.** `unifi_execute_write_action` is absent from the tool list entirely
until you set `UNIFI_ENABLE_WRITES`. No tool argument, prompt, or elicitation can enable
writes at runtime. A tool that cannot write cannot be talked into destroying anything.

Write enablement is granular by service: you can enable Mobility writes without enabling
Protect device operations.

**Over HTTP there is a second gate.** `UNIFI_ENABLE_WRITES` was authored for a threat model
in which the caller had already started the process; switching transport must not silently
widen it. So writes over the HTTP serving transport need `UNIFI_HTTP_ALLOW_WRITES` as well,
and the effective set is the intersection of the two. Its default is `none`, which means an
existing stdio configuration moved to HTTP unchanged serves no writes until you say so
again — and the server prints an upper-case warning at startup saying exactly that, so the
absence is never silent.

### Operations we do not ship

Some operations are not undoable from a chat window and their blast radius exceeds any
conversational benefit. These are absent from the registry in **every** configuration,
including one with all writes enabled — not gated, not confirmed, not built:

| Operation | Why |
|---|---|
| Network device `RESTART` | Drops every client on the device; you may be reaching the controller *through* it |
| Port `POWER_CYCLE` | Drops whatever is on that port, including uplinks and cameras |
| Device adoption | Rewrites ownership and credentials; recovery usually needs physical access |
| Device removal (un-adopt) | Removes and resets the device off the network |
| Delete network | Severs every client on it and destroys its configuration |
| Delete WLAN (`wifi/broadcasts`) | Disconnects every wireless client and loses the PSK |
| Protect `disable-mic-permanently` | The vendor named it "permanently"; there is no API path back |

Reversible mutations — guest-access authorisation, camera and device settings — are *gated*
rather than blocked: available once writes are enabled, and marked destructive so the host
prompts.

Two of these are request *variants* rather than whole endpoints: Network exposes reboot and
power-cycle as discriminator values inside generic `.../actions` endpoints, so those endpoints
stay available with only the dangerous variant withheld.

### Untrusted data

Device names, client hostnames, SSIDs, and camera names are **attacker-influenceable** — they
come from whatever is on your network. They reach tool output and therefore the model's
context. The server bounds their length, strips control and bidirectional-override characters,
and renders them inside a labelled untrusted-data region in the text content. Structured
output carries the original bytes unmodified.

## Working on it

```bash
npm run typecheck      # strict tsc
npm test               # node:test suite
npm run specs:verify   # vendored spec digests + operation counts (no network)
npm run coverage:check # every spec operation registered or blocklisted → coverage-report.json
npm run budget:check   # advertised tool-schema token budget
npm run lint:tools     # annotations, name limits, prompt-injection patterns in descriptions
npm run inspect        # MCP Inspector against the built server
```

Verification is [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector), both
interactively and via `--cli` in CI. There is no bespoke MCP harness.

### The vendored specs

The four OpenAPI specs are **committed to this repository** at pinned versions under `specs/`,
with SHA-256 digests in `specs/manifest.json`. The server reads them from disk and starts with
no network access at all.

Ubiquiti serves these specs as **JSON only** — there is no YAML variant published anywhere on
the portal.

The version segment in a spec URL **must be pinned**. `https://developer.ui.com/network/latest/openapi.json`
returns HTTP 200 with the documentation site's HTML shell, not a spec, so every fetch is
validated as an actual OpenAPI document before anything is written.

`npm run specs:refresh` bootstraps from `https://developer.ui.com/llms.txt`, compares against
what is vendored, and — where anything differs — **prepares** a pull request: it writes the
new spec files and manifest, creates a local branch, commits, and writes a pull-request body
file carrying an operation-level diff. It then prints the `git push` and `gh pr create`
commands and stops. **It does not open the pull request.** It never pushes and never calls
the GitHub API; opening it is a deliberate human step, and merging remains the only path.
Version bumps are reviewed, never silently absorbed: Ubiquiti adds endpoints, adds and
reorders response properties, and changes the format of opaque strings **without advance
notice**, so responses are parsed permissively and never strictly validated.

Two quirks worth knowing if you read the specs yourself:

- **Network and Protect declare no `securitySchemes` and no `security` block at all.** A client
  generated straight from those specs would send unauthenticated requests. This server injects
  the `X-API-Key` header for them unconditionally and asserts that precondition at startup.
- **Protect's spec reports `info.version: "0.0.0"`** — a stub. The URL version segment
  (`7.1.87`) is authoritative and is what the server reports. Protect also supplies **no
  `operationId` on any of its 73 operations**, so action IDs there are synthesised
  deterministically from method and path.

## License

[MIT](LICENSE) — covers the code in this repository.

The OpenAPI documents under `specs/` are Ubiquiti's, vendored verbatim from
`developer.ui.com` and redistributed here so the server can start without network access.
They are not covered by the MIT grant above and remain subject to whatever terms Ubiquiti
applies to them. This project is not affiliated with or endorsed by Ubiquiti Inc.
