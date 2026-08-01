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

| Variable | Purpose |
|---|---|
| `UNIFI_API_KEY` | Cloud key. Serves Site Manager, Mobility, and all Cloud Connector traffic. |
| `UNIFI_LOCAL_HOST` | Console hostname/IP for local-direct Network and Protect. |
| `UNIFI_LOCAL_API_KEY` | Key bound to that console. |
| `UNIFI_CONSOLE_ID` | Console ID for Cloud Connector mode. Get it from `unifi_list_consoles`. |
| `UNIFI_NETWORK_TRANSPORT` | `local` or `connector`. |
| `UNIFI_PROTECT_TRANSPORT` | `local` or `connector`. |
| `UNIFI_LOCAL_CA_BUNDLE` | Path to a CA bundle that trusts your console's certificate. |
| `UNIFI_LOCAL_TLS_INSECURE` | Explicit opt-in to skip certificate verification. See below. |
| `UNIFI_ENABLE_WRITES` | Comma-separated services whose write operations to expose. Empty by default. |

Keys are read from the **OS keychain** first (via `keytar`) and fall back to environment
variables for headless and CI use. The server never writes a key to disk. When it falls back
to environment variables it says so on stderr.

`keytar` is an optional native dependency — if it fails to build, the server still runs on the
environment-variable path.

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
what is vendored, and opens a pull request carrying an operation-level diff. Version bumps are
reviewed, never silently absorbed: Ubiquiti adds endpoints, adds and reorders response
properties, and changes the format of opaque strings **without advance notice**, so responses
are parsed permissively and never strictly validated.

Two quirks worth knowing if you read the specs yourself:

- **Network and Protect declare no `securitySchemes` and no `security` block at all.** A client
  generated straight from those specs would send unauthenticated requests. This server injects
  the `X-API-Key` header for them unconditionally and asserts that precondition at startup.
- **Protect's spec reports `info.version: "0.0.0"`** — a stub. The URL version segment
  (`7.1.87`) is authoritative and is what the server reports. Protect also supplies **no
  `operationId` on any of its 73 operations**, so action IDs there are synthesised
  deterministically from method and path.

## License

MIT
