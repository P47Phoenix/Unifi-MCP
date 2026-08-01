# Product Requirements Document

**Product / Feature:** UniFi MCP — a Model Context Protocol server over all four published Ubiquiti UniFi developer APIs
**Version:** 1.0
**Author:** Product Owner (delivery-team)
**Status:** Draft
**Last Updated:** 2026-08-01

**Repository:** `/var/home/meconnelly/Documents/GitHub/Unifi-MCP` (greenfield — one commit, `README.md`, `.gitattributes`)
**Source brief:** `docs/prd-brief.md`
**Implementation vehicle:** the `mcp-server-dev:build-mcp-server` skill. This PRD is written to serve as that skill's design brief so it can skip its discovery phase entirely.

---

## 1. Problem Statement

A network operator who already administers UniFi gear has exactly two ways to ask a question about their own network today:

1. Click through the UniFi console UI, one page at a time, per site, per console.
2. Hand-roll `curl` against four separate developer APIs that share a vendor and share almost nothing else — three different pagination schemes (opaque cursor, offset/limit, and none at all), three different error envelopes, two different base hosts, a proxy path form that the vendor's own documentation contradicts itself on, and two specs that declare no authentication scheme whatsoever despite requiring one.

Neither path is conversational, and neither composes. "Which of my cameras went offline this week, and were any of them on the same switch port as a client that got blocked?" spans Protect, Network, and Site Manager, and there is no single surface that answers it.

Meanwhile the operator's LLM client (Claude Code, Claude Desktop) is already the place they think about their infrastructure. What is missing is a tool surface.

**Why now.** Ubiquiti has, as of 2026-08-01, published machine-readable OpenAPI specifications for all four APIs, plus per-service `llms.txt` flattened endpoint listings and `ai-gettingstarted.md` guides at a predictable URL pattern. The vendor has explicitly built for LLM consumption. The Cloud Connector — which reaches on-premises Network and Protect controllers through `api.ui.com` with no VPN — removes the last structural reason a tool like this had to live inside the LAN perimeter for cloud-reachable use cases. The raw material exists; the integration does not.

**Who has the problem.** Home-lab and prosumer operators running a single console, and multi-site administrators (MSPs, IT teams) running tens of consoles under an organization key. They have different topologies but the identical complaint: four APIs, one network, no unified way to ask.

**What we are building.** One MCP server. One credential story. One consistent tool surface over Site Manager, Network, Protect, and Mobility — all four, not a subset — reachable in cloud-direct, local-direct, and Cloud-Connector-proxied topologies, with the transport chosen by configuration rather than by calling different tools.

---

## 2. Goals & Success Metrics

Baselines are honestly "none — greenfield" wherever no prior artifact exists. That is not a hedge; it is the accurate baseline for a repository with one commit.

| # | Goal | Metric | Target | Baseline |
|---|------|--------|--------|----------|
| G-1 | Complete coverage of all four published APIs | Percentage of operations in the four vendored OpenAPI specs reachable through the MCP tool surface, computed by an automated coverage check that enumerates every `paths.*.{get,post,put,patch,delete}` entry in the vendored specs and asserts a corresponding action-registry entry | 100% of `GET` operations; 100% of mutating operations minus the explicitly published Never-Ship blocklist (FR-46); zero unaccounted-for operations (every spec operation is either reachable or blocklisted with a stated reason) | None — greenfield |
| G-2 | One consistent surface over inconsistent APIs | Number of distinct pagination contracts and distinct error contracts a client must handle | Exactly 1 pagination contract and exactly 1 error contract across all four APIs, verified by contract tests that exercise at least one list endpoint and one error path per API | 4 pagination behaviours / 4 error envelopes today |
| G-3 | Context economy — the tool surface does not crowd out the conversation | Total token cost of all tool schemas advertised at `tools/list` with the default configuration, measured by a repo script | ≤ 3,000 tokens with all four APIs enabled; ≤ 1,500 tokens with a single API enabled | None — greenfield; naive one-tool-per-operation would exceed 25,000 |
| G-4 | Time-to-first-successful-call for a new user | Elapsed wall-clock time from a clean install to a successful `unifi_list_sites` response, measured on a scripted walkthrough by someone who has not seen the repo | ≤ 10 minutes for the cloud-only path; ≤ 20 minutes for the local-direct path including certificate handling | None — greenfield |
| G-5 | Never blow the host's payload ceiling | Percentage of tool responses exceeding 150,000 characters, measured across the smoke-test corpus and a synthetic large-estate fixture | 0% — every response is bounded in-server and states its truncation | None — greenfield; Protect list endpoints are unpaginated and unbounded by construction |
| G-6 | Safe by default | Percentage of state-changing operations reachable without an explicit, documented opt-in configuration step | 0% — verified by a test that boots the server with default configuration and asserts the write tool is absent from `tools/list` | None — greenfield |
| G-7 | Survives vendor drift without a code change | Number of production breakages attributable to Ubiquiti adding fields, reordering fields, or changing opaque-string formats, over the first 90 days after M5 | 0 — enforced by a test suite that injects unknown fields, `null` values, and absent optional fields into every response fixture and asserts no error | None — greenfield |
| G-8 | Spec freshness is a reviewed event, not a silent one | Percentage of vendored-spec version bumps that land via a reviewed pull request with a machine-generated operation diff attached | 100% | None — greenfield |
| G-9 | Directory-review readiness | Count of `mcp-server-dev:build-mcp-server` non-negotiable constraints (NFR-01 … NFR-10) failing an automated lint of the built server's `tools/list` output | 0 | None — greenfield |

---

## 3. User Personas

### Primary: Dana — single-site home-lab owner

Runs one UniFi console (a Dream Machine class device) at home, on a private RFC1918 address, with the stock self-signed TLS certificate. Has a handful of Protect cameras, 40–80 clients, one site. Uses Claude Desktop on a laptop that is usually on the same LAN. Created an API key on the local console under Integrations. Does not have, and does not want, an organization. Does not use the Cloud Connector because the controller is one hop away.

**Key need:** ask questions about their own network in plain language, from the machine they are already sitting at, without a VPN, a reverse proxy, or a certificate authority. **Their blocker:** the self-signed certificate. Every naive HTTP client fails on their setup, and the "fix" that circulates on forums is to disable TLS verification globally, which is not acceptable as a default.

**What they will not tolerate:** a tool that reboots an access point because a model misread a sentence. Dana's network is their house.

### Primary: Marcus — multi-site MSP administrator

Administers 30–60 UniFi consoles across client sites under a single UniFi organization. Holds an organization API key created at `unifi.ui.com`. Has no VPN into most client networks and is not going to build one. Uses Claude Code from a workstation and increasingly from CI-adjacent automation. Cares about fleet-level questions ("which consoles are on firmware below X", "which sites have an offline device right now") far more than about a single client's DHCP lease.

**Key need:** reach on-premises Network and Protect controllers at client sites through the Cloud Connector, addressed by `consoleId`, without touching each site's LAN. **Their blockers:** discovering `consoleId` values in the first place, and the Connector's 100 requests/minute *per console* budget, which is the binding constraint on any fleet-wide sweep. A tool that fans out naively across 60 consoles will rate-limit itself into uselessness.

**Distinguishing constraint versus Dana:** Marcus lives in transport mode 3 (Connector) and organization-scoped keys; Dana lives in transport mode 2 (local direct) and an owner-scoped key. They exercise different code paths for the same tools, which is precisely why transport must be configuration, not a tool-selection decision.

### Secondary: Priya — cloud-only fleet reporter

Has Site Manager access and nothing else — no local console credentials, no interest in per-client detail. Wants inventory, host/console listings, ISP metrics, and device rollups for reporting. Site Manager keys are read-only today, which suits her exactly. She is the persona that proves the server must be *useful* with only a cloud key and zero host configuration.

**Key need:** minimal viable configuration — one API key, no host, no console ID, no TLS decisions — and a working tool surface.

### Secondary: Sam — Mobility operator

Manages UniFi Mobility for a workspace: cellular/data-plan-backed devices with an active cloud subscription. Is a workspace Admin. Needs `read:mobility` for inspection and `write:mobility` for the PUT operations that change device configuration. Is the persona most likely to hit a 403 caused by a *missing app scope on the key* rather than by a missing permission — a failure mode that is invisible unless the server names it.

**Key need:** an error path that says "your key lacks the `mobility` app scope; regenerate it at unifi.ui.com with that scope enabled" instead of "403 Forbidden". And an unambiguous signal that a Mobility PUT succeeded, given that Mobility PUTs return HTTP 204 with an empty body.

---

## 4. User Stories (Summary)

Stories are grouped by persona. Full Given/When/Then acceptance criteria live in the FR table (Section 5); the mapping column names the FRs that satisfy each story.

| ID | Story title | Persona | Satisfied by |
|---|---|---|---|
| US-01 | Install and reach my cloud estate with one API key and no host configuration | Priya | FR-09, FR-13, FR-22, FR-40 |
| US-02 | Discover my consoles and their IDs without leaving the chat | Marcus, Dana | FR-23, FR-41 |
| US-03 | Query my local controller over its self-signed certificate without disabling TLS globally | Dana | FR-06, FR-11, NFR-14 |
| US-04 | Reach a client site's Network controller through the Cloud Connector with no VPN | Marcus | FR-07, FR-08, FR-42 |
| US-05 | Ask a natural-language question and have the server find the right API operation | All | FR-14, FR-15 |
| US-06 | List sites, consoles, devices, clients, and cameras without paying a search round-trip | All | FR-16 |
| US-07 | Page through a large result set the same way regardless of which API answered | All | FR-18, FR-19 |
| US-08 | Get one comprehensible error shape with a next step, whichever API failed | All | FR-20, FR-21 |
| US-09 | Filter Network results with expressive, validated criteria instead of a hand-built string | Marcus | FR-26, FR-27 |
| US-10 | See a bounded, honestly-labelled response instead of a truncated wall of JSON | All | FR-35, FR-36, FR-37 |
| US-11 | Keep the server read-only by default and opt in deliberately to writes | Dana, Marcus | FR-38, FR-39, G-6 |
| US-12 | Know that certain irreversible operations are simply not shippable | Dana | FR-38 |
| US-13 | Read Protect camera and device state despite Protect having no pagination | Dana | FR-30, FR-31, FR-32 |
| US-14 | Use Mobility with a correctly-scoped key and be told plainly when the scope is missing | Sam | FR-33, FR-34 |
| US-15 | Confirm a Mobility PUT succeeded even though it returns an empty body | Sam | FR-34 |
| US-16 | Not pay context cost for APIs I do not own | Dana, Priya | FR-17, G-3 |
| US-17 | Store my API key in the OS keychain, never in plaintext, never in the transcript | All | FR-10, FR-12, NFR-12, NFR-13 |
| US-18 | Pin a spec version that matches my controller firmware | Dana, Marcus | FR-03, FR-04 |
| US-19 | Have a firmware/spec bump arrive as a reviewable diff, not a surprise | Repo maintainer | FR-02, FR-05 |
| US-20 | Not have a malicious SSID or device name steer the model | All | FR-43, FR-44 |
| US-21 | Verify the built server with MCP Inspector rather than an invented harness | Repo maintainer | FR-45, M3/M4 |
| US-22 | Keep working when Ubiquiti adds fields without notice | All | FR-46, NFR-11 |

---

## 5. Functional Requirements

Priorities use MoSCoW: **Must Have**, **Should Have**, **Could Have**. Every FR carries at least one acceptance criterion phrased as a present-tense assertion or a "must" — no "should", "might", or "could" appears inside an acceptance criterion.

### 5.1 Spec ingestion and version management

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-01 | The four OpenAPI specifications are vendored into the repository as build inputs under a versioned directory (`specs/{service}/{version}/openapi.json`), fetched only from pinned-version URLs. The canonical sources are `https://developer.ui.com/site-manager/v1.0.0/openapi.json` (OpenAPI 3.0.3), `https://developer.ui.com/network/v10.4.57/openapi.json` (3.1.0), `https://developer.ui.com/protect/v7.1.87/openapi.json` (3.1.0), and `https://developer.ui.com/mobility/v1.0.0/openapi.json` (3.0.3). | Must Have | • The repository contains all four spec files at the pinned versions above, committed, with a recorded SHA-256 for each. • The server starts and serves a complete tool surface with no network access to `developer.ui.com` at runtime. • A grep of the repository for the literal string `/latest/openapi.json` returns zero matches in any code path that fetches a spec. |
| FR-02 | The spec-refresh routine bootstraps from `https://developer.ui.com/llms.txt`, which indexes all four services, their current versions, and every spec URL. It resolves current versions, fetches the pinned-version JSON for each, and opens a pull request when any differs from the vendored copy. | Must Have | • Running the refresh command against a stubbed index that advertises a newer Network version produces a branch containing the new spec file and an operation-level diff report, and does not modify the previously vendored version. • The refresh command never commits directly to the default branch. • The refresh command exits non-zero and changes nothing when the index cannot be retrieved. |
| FR-03 | Every fetched spec response is validated as an OpenAPI document before it is written to disk: the body must parse as JSON and must contain an `openapi` version string and a non-empty `paths` object. A response that is HTML is rejected. | Must Have | • Given a fetch that returns HTTP 200 with an HTML document body (the failure mode produced by an unpinned `latest` URL), the routine fails with a message naming the URL and the reason, and writes no file. • Given a 200 response with a valid OpenAPI body, the file is written and its SHA-256 recorded. |
| FR-04 | Users on older controller firmware can pin a matching spec version for Network and Protect. The server accepts a configured spec version per service and loads the vendored spec for that version; older versions remain fetchable from the same URL pattern (for example `https://developer.ui.com/network/v9.1.120/openapi.json`) and can be vendored alongside the current one. | Must Have | • With Network pinned to a vendored older version, `tools/list` and the action registry reflect only operations present in that spec. • Requesting a spec version that is not vendored produces a structured startup error naming the missing version and the vendoring command, and the server does not start with a silently substituted version. |
| FR-05 | Spec version bumps are reviewed, not absorbed. The refresh pull request body contains a machine-generated diff listing added operations, removed operations, added/removed parameters, and added/removed response properties. | Must Have | • The generated PR body enumerates every operation added and removed between the vendored and candidate spec. • A refresh producing zero operation-level differences still records the version change and the new SHA-256. • Merging the PR is the only path by which the vendored spec files change. |
| FR-06 | Because the Network and Protect specs declare **no `securitySchemes` and no `security` block at all**, the ingestion pipeline performs an explicit, documented post-processing auth-injection step for those two services, and asserts its own precondition. | Must Have | • The pipeline emits a warning naming Network and Protect when it detects an absent `securitySchemes`, and injects the API-key header requirement into the generated client for those services. • A test asserts that a request built for any Network or Protect operation carries the API key header. • If a future spec version *does* declare `securitySchemes`, the pipeline emits a notice that the injection step may now be redundant rather than silently double-applying it. |

*(Assumption A-3, Section 13, records why JSON→YAML conversion is excluded.)*

### 5.2 Transport topology

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-07 | The server supports **cloud-direct** transport for Site Manager (`https://api.ui.com`) and Mobility (`https://api.ui.com/v1/mobility`) with no host configuration and standard public TLS verification. | Must Have | • With only an API key configured and no host, console ID, or TLS option set, a Site Manager list call and a Mobility list call both succeed. • Certificate verification is enabled for these hosts and cannot be disabled by the local-TLS opt-in of FR-09. |
| FR-08 | The server supports **local-direct** transport for Network at `https://{host}/proxy/network/integration` and Protect at `https://{host}/proxy/protect/integration`, with `{host}` user-supplied. | Must Have | • With a host configured, Network and Protect operations route to the local base URLs above. • The same tool names and the same argument shapes are used as in Connector mode; no tool name encodes the transport. |
| FR-09 | UniFi consoles ship self-signed TLS certificates. Local-direct mode therefore requires an **explicit, clearly-named opt-in** to relax verification, and/or a custom CA bundle path. Verification is enabled by default and defaulting to insecure is prohibited. | Must Have | • With a host configured and no TLS option set, a request to a self-signed console fails with a structured error that names the certificate problem and lists exactly two remedies: supply a CA bundle path, or set the named insecure opt-in. • The insecure opt-in is a single explicitly-named boolean setting (`UNIFI_LOCAL_TLS_INSECURE`) whose name contains the word `insecure`. • Setting the opt-in relaxes verification **only** for configured local console hosts and never for `api.ui.com`. • When the opt-in is active, the server emits a startup warning to stderr naming the affected hosts. |
| FR-10 | The server supports **Cloud Connector** transport, reaching on-premises Network and Protect through `https://api.ui.com/v1/connector/consoles/{consoleId}/proxy/network/integration/...` and `.../proxy/protect/integration/...`. The `/proxy/...` path form is used, per the `servers[]` entries in the Network and Protect specs, the path-parameter example, and `ai-gettingstarted.md`. | Must Have | • A Connector-mode request for a Network operation produces a URL containing `/v1/connector/consoles/{consoleId}/proxy/network/integration/`. • The same holds for Protect with `/proxy/protect/integration/`. • The path form used is asserted by a unit test with a recorded reference to the doc inconsistency (OQ-06). |
| FR-11 | Transport for Network and Protect is selected by **configuration**, not by tool choice. One tool surface serves both local-direct and Connector modes. | Must Have | • The set of tool names advertised at `tools/list` is byte-identical between a local-direct configuration and a Connector configuration with the same enabled APIs. • Switching a configuration value from local-direct to Connector changes only the resolved base URL, verified by a request-builder test. |
| FR-12 | Connector-specific documented constraints are enforced client-side: console firmware ≥ 5.0.3, **100 requests/minute per console**, a 25-second per-request timeout, and a 10 MB response body cap. Non-organization keys reach only the key owner's consoles; organization keys reach any console in the organization. | Must Have | • A per-console token bucket limits outbound Connector requests to 100/minute and a burst beyond that is queued or rejected with a structured rate-limit error carrying a retry hint, never silently dropped. • A Connector request exceeding 25 seconds is abandoned with a structured timeout error naming the console ID. • A response body exceeding 10 MB is rejected with a structured error instructing the caller to narrow the query, and is not buffered whole into the transcript path. • A Connector call against a console below firmware 5.0.3 surfaces the firmware requirement in the error text. |

### 5.3 Authentication and credentials

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-13 | All four APIs authenticate with an API key sent in the `X-API-Key` HTTP header. The server sets this header on every outbound request to every API, including Network and Protect where the spec declares no security scheme. | Must Have | • Every outbound request recorded by the request-builder test suite carries an `X-API-Key` header. • Header matching on inbound configuration is case-insensitive, consistent with HTTP header semantics. |
| FR-14 | The server supports **multiple credentials**: one cloud key (used for Site Manager, Mobility, and all Cloud Connector traffic) and zero or more local console keys, each bound to a configured console host. | Must Have | • With a cloud key and one local key configured, a Site Manager call uses the cloud key and a local-direct Network call to the bound host uses the local key, verified by request inspection. • A local-direct request to a host with no bound credential fails with a structured error naming the host and the configuration key required. • A Connector-mode Network call uses the cloud key, not a local key. |
| FR-15 | API keys are read from OS-keychain-backed storage, with an environment-variable path for headless and CI use. Keys are never written to plaintext files by the server. | Must Have | • A test asserts the server writes no file containing a configured key value anywhere under the user's config or state directories. • With a key present in the keychain and absent from the environment, the server authenticates successfully. • With the keychain unavailable, the server falls back to environment variables and logs, to stderr, that keychain storage is not in use. |
| FR-16 | Elicitation is never used to collect API keys or any other credential. | Must Have | • A grep of the source for elicitation request construction returns zero call sites whose prompt text references a key, token, secret, or password. |
| FR-17 | Site Manager keys are read-only today. The server treats Site Manager as a read-only API and states in its documentation that when Ubiquiti ships write endpoints, existing keys will not gain write access automatically — a manual key update will be required. | Must Have | • No Site Manager operation is exposed through the write execution tool. • The Site Manager section of the README states the manual-key-update requirement verbatim in substance. |

### 5.4 Tool surface

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-18 | The tool surface follows the **hybrid search + execute** pattern (see ADR-02): a small set of promoted read tools plus `unifi_search_actions` and two execution tools. The four specs total well over the 30-operation threshold at which one-tool-per-operation is prohibited. | Must Have | • `tools/list` with all four APIs enabled returns no more than 12 tools. • The total token cost of the advertised schemas is ≤ 3,000 tokens, asserted by a repo script (G-3). |
| FR-19 | `unifi_search_actions` accepts a natural-language intent string and optional service/method filters, and returns matching action IDs with their input schemas, HTTP method, owning service, and a read/write classification. | Must Have | • Given the query "which access points are offline", the tool returns at least one Network device-listing action ID with its schema. • Given a query matching nothing, the tool returns an empty result set with a text hint naming the enabled services, not an error. • Every returned action ID is directly usable as input to an execution tool without transformation. • Results are bounded by a documented `limit` parameter with a default and a hard maximum. |
| FR-20 | `unifi_execute_action` executes a **read-only** action by ID. `unifi_execute_write_action` executes a **state-changing** action by ID. They are separate tools; neither accepts the other's action class. | Must Have | • `unifi_execute_action` given a write action ID returns a structured tool error stating the action is state-changing and naming the write tool, and performs no HTTP request. • `unifi_execute_write_action` given a read action ID returns a structured tool error naming the read tool. • `unifi_execute_write_action` is absent from `tools/list` under default configuration (G-6). |
| FR-21 | Exactly five operations are promoted to dedicated tools, chosen because they are the entry points from which every other question is reachable and are the operations a first-time user calls before anything else: `unifi_list_consoles`, `unifi_list_sites`, `unifi_list_devices`, `unifi_list_clients`, `unifi_list_cameras`. Rationale per tool is recorded in ADR-02. | Must Have | • All five tools appear in `tools/list` when their owning API is enabled and are absent when it is not. • Each is callable with zero required arguments and returns a useful first page. • Each carries `readOnlyHint: true`. • Each tool description names the sibling tools it is most likely to be confused with. |
| FR-22 | Tool exposure is filterable by configuration so a user who owns no Protect gear does not pay for Protect schemas. Each of the four APIs can be independently enabled or disabled. | Must Have | • With Protect disabled, `unifi_list_cameras` is absent from `tools/list`, `unifi_search_actions` returns no Protect actions, and the advertised schema token count drops measurably. • With a single API enabled, advertised schema token cost is ≤ 1,500 tokens. • Disabling an API the user has not configured credentials for is the default, not an opt-out. |

### 5.5 Normalized pagination and errors

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-23 | One **normalized pagination contract** spans all four APIs. The server exposes a single cursor-shaped interface (`cursor` in, `next_cursor` out, plus `page_size`) and internally translates to each API's native scheme: Site Manager's opaque `nextToken` with `pageSize` (max 500); Network's `offset`/`limit` (default 25, max 200) with its `{count, data[], limit, offset, totalCount}` envelope; Mobility's `offset`/`limit` (default 200) with its `{data[], total, offset, limit, httpStatusCode, traceId}` envelope, advancing `offset` until `offset >= total`; and Protect, which has **no pagination at all** and returns full arrays from parameterless list endpoints. | Must Have | • A paged read against each of the four APIs returns the same envelope field names. • For Site Manager, the returned `next_cursor` round-trips to the next page and `page_size` above 500 is rejected in-schema. • For Network, `page_size` above 200 is rejected in-schema and `total_count` is populated from `totalCount`. • For Mobility, iteration terminates when `offset >= total` and does not loop. • For Protect, the server applies server-side slicing over the full array, returns a synthetic cursor, and the response states that pagination is emulated because the upstream API provides none. |
| FR-24 | One **normalized error contract** spans all four APIs. The server maps Site Manager's `{code, httpStatusCode, message, traceId}` (codes `BAD_REQUEST`, `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`, `RATE_LIMIT`, `SERVER_ERROR`, `BAD_GATEWAY`); Network's `{code, message, requestId, requestPath, statusCode, statusName, timestamp}` with dotted codes such as `api.authentication.missing-credentials`; Mobility's `{code, httpStatusCode, message, traceId}`; and Protect's `genericError` shape of `{error, name}` onto a single normalized error object carrying a stable category, the upstream code verbatim, a human-readable message, the correlation identifier where one exists, and the originating service. | Must Have | • A fixture-driven test feeds one authentic error body per API and asserts identical normalized field names across all four. • The upstream code is preserved verbatim and is never rewritten or lost. • Protect errors, which carry no correlation identifier, produce a normalized error with a null correlation field rather than a fabricated one. |
| FR-25 | Mobility's gateway-versus-upstream distinction is preserved: a present `body.code` in a Mobility error means the error originated at the gateway rather than the upstream service, and the normalized error records that origin. | Must Have | • Given a Mobility error body containing `code`, the normalized error's origin field reads `gateway`. • Given a Mobility error body without `code`, the origin field reads `upstream`. |
| FR-26 | Rate limiting is handled uniformly. Site Manager returns HTTP 429 with a `Retry-After` header on its published limits (10,000 req/min on stable `/v1/`, 100 req/min on Early Access `/ea/`); the Cloud Connector enforces 100 req/min per console. The server honours `Retry-After`, applies bounded retry with backoff for idempotent reads, and never silently retries a state-changing request. | Must Have | • Given a 429 with `Retry-After: 5`, a read retries no sooner than 5 seconds later and at most the configured maximum attempts. • A 429 on a write operation is surfaced to the caller as a structured error with a retry hint and is not retried automatically. • Retry behaviour and its bounds are configurable and documented. • Mobility and local Network/Protect rate limits are not hard-coded pending OQ-01 and OQ-02; the server applies a conservative configurable default and records that it is provisional. |

### 5.6 Site Manager (cloud, read-only)

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-27 | Every Site Manager operation in the vendored `v1.0.0` spec is reachable via `unifi_search_actions` + `unifi_execute_action`. | Must Have | • The coverage check reports 100% of Site Manager spec operations present in the action registry. |
| FR-28 | `unifi_list_consoles` returns the hosts/consoles visible to the configured key, including each console's identifier in the exact form the Cloud Connector path expects, and its firmware version. | Must Have | • The returned console identifier is directly substitutable into the Connector `{consoleId}` path segment without transformation. • The response includes firmware version so a caller can determine Connector eligibility (≥ 5.0.3) without a second call. • With a non-organization key, only the key owner's consoles are returned, and the tool description states this. |
| FR-29 | `unifi_list_sites` returns the sites visible to the configured key with their identifiers and owning console. | Must Have | • Each returned site carries an identifier usable as an argument to Network operations. • The response links each site to the console that hosts it. |
| FR-30 | Site Manager Early Access (`/ea/`) operations, where present in the spec, are marked as Early Access in their action metadata and carry the 100 req/min limit rather than the 10,000 req/min stable limit. | Should Have | • An action whose path is under `/ea/` is flagged Early Access in `unifi_search_actions` results. • Rate limiting for `/ea/` paths uses the 100 req/min bucket. |

### 5.7 Network

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-31 | Every Network operation in the vendored `v10.4.57` spec is reachable, in both local-direct and Connector transport modes. | Must Have | • The coverage check reports 100% of Network spec operations present in the action registry. • A representative Network read succeeds in both transport modes against recorded fixtures. |
| FR-32 | `unifi_list_devices` and `unifi_list_clients` are first-class read tools over Network device and client inventory, each accepting a site identifier, the normalized pagination arguments, and the structured filter of FR-33. | Must Have | • Both tools return within the normalized pagination envelope. • Both accept and correctly apply a site identifier. • Both carry `readOnlyHint: true` and a description naming the other as its near-sibling. |
| FR-33 | Network's `filter` query DSL is modelled as a **structured, validated input** rather than passed through as an opaque string. The model covers property expressions (`id.eq(123)`, `name.like('guest*')`, `createdAt.in(2025-01-01, 2025-01-05)`), compound `and(...)` / `or(...)`, negation `not(...)`, the types STRING (single-quoted, `''` escapes a quote), INTEGER, DECIMAL, TIMESTAMP (ISO 8601), BOOLEAN, UUID and SET, and the functions `isNull`, `isNotNull`, `eq`, `ne`, `gt`, `ge`, `lt`, `le`, `like`, `in`, `notIn`, `isEmpty`, `contains`, `containsAny`, `containsAll`, `containsExactly`. | Must Have | • A structured filter for `name.like('guest*')` serialises to exactly that DSL string. • A STRING literal containing a single quote serialises with the quote doubled. • A TIMESTAMP value not in ISO 8601 form is rejected in-schema before any HTTP request. • An unsupported function name is rejected in-schema with an error listing the supported functions. • Compound and negated expressions nest to at least three levels and serialise correctly. |
| FR-34 | A raw filter-string escape hatch exists, is separate from the structured input, and is documented as unvalidated. | Should Have | • Supplying both the structured filter and the raw string is rejected with a structured error naming the conflict. • The raw string is passed through byte-for-byte. |

### 5.8 Protect

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-35 | Every Protect operation in the vendored `v7.1.87` spec is reachable, in both local-direct and Connector transport modes. The URL version segment is authoritative for the Protect spec version; the spec's own `info.version` reports `"0.0.0"` and is a stub that must not be used as an identifier anywhere in the product. | Must Have | • The coverage check reports 100% of Protect spec operations present in the action registry. • A grep of generated artefacts and user-facing strings for a Protect version of `0.0.0` returns zero matches. • The Protect version reported by any server introspection reads `7.1.87`. |
| FR-36 | `unifi_list_cameras` is a first-class read tool over Protect cameras, presenting the normalized pagination envelope over Protect's unpaginated full-array response via server-side slicing. | Must Have | • The tool returns the normalized envelope with a synthetic cursor. • The response text states that pagination is emulated server-side. • The default page size is bounded in-schema. |
| FR-37 | Because Protect list endpoints accept no query parameters and return complete arrays, every Protect list action applies server-side field projection and slicing before the response reaches the transcript. | Must Have | • A Protect list response of 500 objects returns a bounded page and a truncation statement naming the total. • A default field projection is applied and the projected field set is documented per resource type. • Requesting the full unprojected object for a single resource by ID remains available as a separate action. |

### 5.9 Mobility

Mobility is the smallest spec and the easiest to under-serve. It gets its own requirements.

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-38 | Every Mobility operation in the vendored `v1.0.0` spec is reachable via search + execute, against the cloud-direct base `https://api.ui.com/v1/mobility`. | Must Have | • The coverage check reports 100% of Mobility spec operations present in the action registry. • Mobility actions route to the `/v1/mobility` base and never through the Connector. |
| FR-39 | Mobility requires a `mobility` **app scope** on the API key, plus `read:mobility` for GET operations and `write:mobility` for PUT operations. The server records these scope requirements in action metadata and states them in tool descriptions. | Must Have | • Each Mobility action's metadata names the scopes it requires. • The Mobility tool descriptions state the `mobility` app scope requirement. • With Mobility enabled and no key configured, startup emits a stderr warning naming the required scopes rather than failing silently. |
| FR-40 | A Mobility 403 caused by a missing app scope produces a **distinct, actionable** normalized error, separate from a generic permission denial: it names the missing scope and states the remediation (regenerate the key at `https://unifi.ui.com` with the `mobility` app scope enabled). | Must Have | • Given a Mobility 403 response, the normalized error's recovery hint names the `mobility` app scope and the key-regeneration location. • The error distinguishes the missing-scope case from the insufficient-role case (caller must be a workspace Admin) and from the missing-subscription case (writes require an active cloud subscription on the target device), and names which applies where the upstream response permits that determination. • Where the upstream response does not permit that determination, the hint enumerates all three candidate causes rather than guessing one. |
| FR-41 | Mobility PUT operations return **HTTP 204 with an empty body**. The server converts a 204 into an explicit success result rather than an empty or null tool response. | Must Have | • Given a 204 from a Mobility PUT, the tool returns a success result whose text names the operation performed and the target device identifier. • The result is not an empty content array, an empty string, or `null`. • `structuredContent` for a 204 carries an explicit success boolean and the echoed target identifier. |
| FR-42 | The server supports the optional client-supplied `X-Request-ID` trace header for Mobility, generating one per request when the caller does not supply it, and surfacing it in both success and error results. | Should Have | • Every Mobility request carries an `X-Request-ID`. • A caller-supplied trace identifier is used verbatim. • The trace identifier appears in the normalized error for any failed Mobility call. |
| FR-43 | Mobility write operations are subject to the same write-gating as all other state-changing operations (FR-46) and additionally state the active-cloud-subscription precondition in their descriptions. | Must Have | • Mobility PUT actions are absent from the read execution tool and present in the write execution tool only when writes are enabled. • The description of the write path names the subscription precondition. |

### 5.10 Read/write posture and destructive operations

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-44 | The default posture is **read-only**. State-changing operations are unavailable until the user sets an explicit configuration flag. | Must Have | • With default configuration, `unifi_execute_write_action` is absent from `tools/list`. • With default configuration, no code path issues a `POST`, `PUT`, `PATCH`, or `DELETE` to any UniFi API, asserted by an outbound-request interceptor in the test suite. • Enabling writes requires setting a named configuration value; no tool argument, prompt, or elicitation can enable writes at runtime. |
| FR-45 | Write enablement is **granular by service and by risk class**, not a single global switch: a user can enable Mobility writes without enabling Protect device operations. | Should Have | • Enabling writes for one service leaves other services' write actions unavailable. • The set of enabled write services is reported by server introspection and named in the write tool's description. |
| FR-46 | A published **Never-Ship blocklist** enumerates operations the server does not expose at all, in any configuration, because they are not undoable from a chat window and their blast radius exceeds any conversational benefit. The proposed initial blocklist is: device adoption and un-adoption; firmware upgrade initiation; factory reset; console or device reboot and power-cycle; and any operation that deletes a site, network, or WLAN. Reboot, adoption, firmware update, and client block are called out in the brief as specifically irreversible from chat; of these, client block is *reversible* and is therefore gated rather than blocked. | Must Have | • Every blocklisted operation is absent from the action registry in every configuration, asserted by a test that boots with all writes enabled and asserts absence. • `unifi_search_actions` returns, for a query matching a blocklisted operation, a text explanation naming the operation and stating that it is deliberately not exposed — not an empty result. • The blocklist lives in a single reviewed file and every entry carries a one-line reason. • The coverage check counts blocklisted operations as accounted-for, not as gaps (G-1). |
| FR-47 | Gated-but-shippable write operations (client block/unblock, port profile changes, Mobility PUTs, Protect camera settings) carry `destructiveHint` and, where applicable, `idempotentHint`, so the host prompts for confirmation. | Must Have | • Every action in the write registry carries an explicit `destructiveHint` value. • Idempotent writes carry `idempotentHint: true`; non-idempotent writes carry `idempotentHint: false`. • No write action carries `readOnlyHint: true`. |

### 5.11 Response size control

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-48 | Every list-shaped tool bounds its result in-schema (`default`, `minimum`, `maximum`) and applies a hard server-side cap independent of the requested size. | Must Have | • Requesting a page size above the schema maximum is rejected before any HTTP request. • A hard cap applies even when the schema maximum is raised by configuration. |
| FR-49 | Truncation is always stated in the response text, naming what was withheld and how to narrow the query. | Must Have | • A truncated response's text contains a count of returned items, a count of total items where known, and a concrete narrowing suggestion — for example `Showing 10 of 847 results. Refine the query to narrow down.` • An untruncated response contains no truncation statement. |
| FR-50 | Field projection is available on read actions, with a documented default projection per resource type and an opt-in full-object mode for single-resource reads. | Should Have | • A projected list response omits fields outside the default projection. • Requesting an explicit field list returns exactly those fields plus the resource identifier. • The full-object mode is unavailable on list actions and available on get-by-id actions. |
| FR-51 | Response size ceilings are verified against a synthetic large-estate fixture representing an implausibly large deployment. | Must Have | • The fixture includes a Protect installation with an unpaginated array large enough to exceed 10 MB unprojected and a Network client list exceeding 5,000 entries. • Every tool exercised against the fixture returns under 150,000 characters. • The test fails the build if any response exceeds the ceiling. |

### 5.12 Configuration and discovery

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-52 | **Minimal viable configuration is one API key.** With a cloud key and nothing else, Site Manager and Mobility work and no host, console ID, or TLS decision is required. | Must Have | • Booting with only a cloud key produces a working Site Manager tool surface. • No startup error or warning demands a host when no local API is enabled. |
| FR-53 | The `consoleId` discovery story is a tool, not documentation: `unifi_list_consoles` returns the identifiers, and the Connector-mode configuration references them. | Must Have | • A user with only a cloud key can obtain every `consoleId` they are entitled to in a single tool call. • The Connector transport error for an unknown or unentitled console ID names `unifi_list_consoles` as the recovery path. |
| FR-54 | Configuration is validated at startup with actionable failures: unknown keys, mutually exclusive combinations (for example a CA bundle path together with the insecure opt-in), and enabled APIs lacking credentials are each reported by name. | Must Have | • Each of the three failure classes above produces a distinct startup message naming the offending setting. • The server does not start in a partially-valid state; either the configuration validates or startup fails. • Warnings for enabled-but-uncredentialed APIs do not prevent startup when at least one API is usable. |
| FR-55 | Server introspection reports the effective configuration with all secret values redacted: enabled APIs, spec versions in use, transport mode per service, and write-enablement state. | Should Have | • The introspection output contains no key material, verified by a test that plants a recognisable sentinel key value and asserts its absence. • The output names the spec version per service. |

### 5.13 Prompt-injection exposure

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-56 | UniFi data contains user-controlled strings — SSIDs, client hostnames, device names, camera names — that flow from the network into tool output and then into the model's context. All such fields are treated as untrusted data and are delimited and labelled as untrusted in tool output. | Must Have | • Every response containing a device, client, camera, or network name emits those values inside a clearly-labelled untrusted-data region in the text content. • The label is present even when the values are benign. • `structuredContent` carries the values verbatim and unmodified; the delimiting applies to the text rendering. |
| FR-57 | Untrusted string fields are length-bounded and control characters are neutralised before entering tool output. | Must Have | • A device name of 10,000 characters is truncated to a documented bound and the truncation is stated. • ASCII control characters and bidirectional-override characters are stripped or escaped in the text rendering. • The original value remains retrievable byte-for-byte via `structuredContent`. |
| FR-58 | Tool descriptions never instruct the model how to behave. | Must Have | • No tool description contains an imperative directing model behaviour (patterns such as "always call", "first call", "you must", "never respond"). • A lint rule enforces this and fails the build on violation. |

### 5.14 Verification and coverage

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| FR-59 | A coverage check enumerates every operation in each vendored spec and asserts that each is either present in the action registry or present in the Never-Ship blocklist with a stated reason. | Must Have | • The check emits per-service counts of covered, blocklisted, and uncovered operations. • Any uncovered operation fails the build. • The counts are written to a committed report file that a reviewer can diff across spec bumps. |
| FR-60 | The server is verified with **MCP Inspector** (`npx @modelcontextprotocol/inspector`), and its `--cli` mode is used for CI smoke tests. No bespoke MCP test harness is invented. | Must Have | • A documented interactive Inspector session exercises each promoted tool and both execution tools. • A CI job runs Inspector in `--cli` mode against the built server, asserts the expected tool list, and invokes at least one read tool per enabled API against recorded fixtures. • The CI job fails the build on a non-zero Inspector exit. |
| FR-61 | The server tolerates undeclared vendor changes: unknown response fields, reordered fields, `null` values in place of objects, absent optional fields, and changed length or format of opaque strings (object identifiers, error messages) are all non-fatal. Strict schema validation is not applied to responses. | Must Have | • A fuzz suite injects each of the five drift classes above into every response fixture and asserts no error and no dropped known field. • No response-validation code path rejects a payload for containing an unrecognised property. • Opaque identifiers are treated as opaque strings with no length or format assertion anywhere in the codebase. |

---

## 6. Non-Functional Requirements

NFR-01 through NFR-10 are the non-negotiable constraints carried directly from `mcp-server-dev:build-mcp-server`. They are stated here as separately testable requirements because directory review checks them.

| ID | Requirement | Type | Target |
|----|-------------|------|--------|
| NFR-01 | Read and write operations are exposed as separate tools. A single tool accepting both is auto-rejected at directory review; documenting safe-versus-unsafe inside one tool's description does not satisfy this. | Compliance / Safety | 0 tools in `tools/list` that accept both read and write action classes, asserted by lint of the built tool manifest |
| NFR-02 | Every tool carries `title`, `readOnlyHint`, and — where applicable — `destructiveHint` and `idempotentHint`. | Compliance | 100% of tools carry `title` and `readOnlyHint`; 100% of non-read-only tools carry `destructiveHint`; lint fails the build on any gap |
| NFR-03 | Every tool description states what the tool does, what it returns, and what it does not do, and disambiguates near-siblings by naming them. | Compliance / Usability | 100% of tools; every tool with a near-sibling names that sibling by exact tool name |
| NFR-04 | No tool description instructs the model how to behave; such text is treated as prompt injection at review. | Compliance / Security | 0 occurrences of behavioural-imperative patterns, enforced by build-failing lint (see FR-58) |
| NFR-05 | Errors are returned as structured MCP tool errors of the shape `{ isError: true, content: [...] }` carrying a recovery hint. Exceptions never propagate to the transport and HTML error bodies are never forwarded. | Reliability | 100% of error paths return a structured tool error; 0 transport crashes across the full fault-injection suite; 100% of error results carry a non-empty recovery hint |
| NFR-06 | Every list parameter is bounded in-schema with `minimum`, `maximum`, and `default`, plus a hard server-side cap. | Reliability | 100% of list-shaped parameters bounded; unbounded parameters fail lint |
| NFR-07 | Truncation is applied and stated. No tool returns an unbounded upstream payload. | Reliability / Usability | 100% of truncated responses include counts and a narrowing suggestion in text |
| NFR-08 | Payload ceilings are respected: claude.ai and Claude Desktop truncate around 150,000 characters; Claude Code around 25,000 tokens. This binds directly on Protect's unpaginated arrays and on large Network client lists. | Performance | 0 responses over 150,000 characters and 0 over 25,000 tokens against the large-estate fixture (FR-51) |
| NFR-09 | Tools prefer `outputSchema` with `structuredContent`, and always include a text fallback, because not all hosts read `structuredContent`. | Compatibility | 100% of tools declare `outputSchema` and return both `structuredContent` and non-empty text content |
| NFR-10 | Tool names are ≤ 64 characters, snake_case, and every parameter carries a description. | Compliance | 100% of tool names match `^[a-z][a-z0-9_]{0,63}$`; 100% of parameters have a non-empty description; lint fails the build on any gap |
| NFR-11 | Responses are parsed permissively. Unknown fields, reordered fields, `null`s, absent optionals, and changed opaque-string formats are non-fatal. | Reliability | 0 failures across the drift fuzz suite (FR-61); 0 strict response validators in the codebase |
| NFR-12 | Credentials never appear in tool results, text content, `structuredContent`, error messages, or logs. Tool results flow into the chat transcript and any log export. | Security | 0 occurrences of a planted sentinel key value in any output channel, asserted by an automated scan across the full smoke-test corpus |
| NFR-13 | Credentials at rest live in the OS keychain (`keytar` on the chosen stack). Never plaintext on disk. MCPB manifest fields carrying credentials are marked `sensitive: true`. | Security | 0 plaintext credential files written by the server; 100% of MCPB credential fields marked sensitive |
| NFR-14 | TLS verification is enabled by default for every host. Relaxation requires the explicitly-named `UNIFI_LOCAL_TLS_INSECURE` opt-in and applies only to configured local console hosts. | Security | Default configuration verifies certificates for 100% of hosts; the opt-in never affects `api.ui.com`, asserted by test |
| NFR-15 | Outbound request rate is bounded per target. Cloud Connector traffic is limited to 100 requests/minute per console; Site Manager `/ea/` paths to 100/minute; Site Manager `/v1/` to 10,000/minute. Limits for Mobility and for local-direct Network/Protect are configurable with a conservative provisional default pending OQ-01 and OQ-02. | Reliability | 0 self-inflicted 429s against the Connector in a 60-console fan-out simulation; all limits configurable without a code change |
| NFR-16 | Cloud Connector requests are abandoned at 25 seconds and responses above 10 MB are rejected, matching the documented Connector constraints. | Reliability | 100% of Connector requests bounded at 25 s; 0 response bodies above 10 MB buffered to completion |
| NFR-17 | The server starts and advertises its tool list without any network access to `developer.ui.com` or `api.ui.com`. | Reliability / Startup | `tools/list` returns successfully with all outbound network blocked; startup completes in ≤ 2 seconds on a mid-range laptop |
| NFR-18 | Total advertised tool-schema token cost is bounded. | Performance / Context economy | ≤ 3,000 tokens with all four APIs enabled; ≤ 1,500 tokens with one API enabled (G-3) |
| NFR-19 | On stdio transport, all diagnostic output goes to stderr. Nothing but protocol frames is written to stdout. | Reliability | 0 non-protocol bytes on stdout across the full test suite |
| NFR-20 | The server runs on macOS, Linux, and Windows, including headless Linux where no keychain daemon is available (falling back to environment variables per FR-15). | Portability | CI matrix green on all three platforms; documented headless-Linux path exercised in CI |
| NFR-21 | Untrusted strings originating from network data are bounded in length and stripped of control and bidirectional-override characters before entering text output. | Security | 100% of name-bearing fields bounded and sanitised in text rendering; original values preserved in `structuredContent` |
| NFR-22 | The action registry and generated schemas are deterministic: the same vendored specs produce byte-identical generated artefacts. | Maintainability | Two clean builds from the same spec SHAs produce identical output hashes |

---

## 7. Out of Scope

Explicitly excluded from this release. Each entry names the reason, because "out of scope" without a reason gets relitigated.

1. **The legacy / undocumented UniFi controller API** (the `/api/s/{site}/...` cookie-session endpoints that community libraries wrap). It is unpublished, unversioned, and unsupported by Ubiquiti; building on it would put the server's stability at the mercy of an interface with no contract. This server covers the four *published developer* APIs only.
2. **UniFi Access, Talk, Drive, and Identity.** No published developer APIs exist for these products as of 2026-08-01. There is nothing to wrap. If Ubiquiti publishes specs at the same `https://developer.ui.com/{service}/{version}/openapi.json` pattern, the ingestion pipeline (FR-01–FR-05) extends to them without redesign — but that is a future release.
3. **Protect live video streaming, RTSP/RTSPS stream handling, WebRTC, two-way talkback, and continuous video export.** Streaming media is not representable in an MCP tool result and would require an out-of-band transport. Single-frame snapshot endpoints, where the vendored Protect spec exposes them, are in scope but return a reference rather than inline image bytes (see FR-37 and NFR-08).
4. **Write access to Site Manager.** Site Manager keys are read-only today. When Ubiquiti ships write endpoints, existing keys will not gain write access automatically, and a manual key update will be required (FR-17). Supporting a capability that does not exist yet is speculative work.
5. **Any user interface beyond the MCP protocol itself.** No web console, no TUI, no dashboard, no CLI beyond the maintainer-facing spec-refresh and coverage commands. The MCP client *is* the interface.
6. **A hosted, multi-tenant remote deployment.** See ADR-01. UniFi publishes no OAuth, and the build skill states that Claude does not support user-pasted bearer tokens (`static_bearer`), so there is no supported mechanism for a hosted server to collect each user's UniFi key. Revisit if and when Ubiquiti publishes OAuth.
7. **A caching layer or local database of UniFi state.** Every read is a live read. A cache introduces staleness questions ("was that camera offline now or an hour ago?") that undermine the product's core value and would need its own invalidation design.
8. **A monitoring or alerting daemon.** The server answers questions when asked; it does not poll, watch, or notify. Long-running background polling is a different product with different rate-limit economics against the Connector's 100 req/min per console.
9. **Publishing YAML specifications.** Ubiquiti serves the specs as **JSON only**; no YAML variant is published anywhere on the portal. A local JSON→YAML conversion is possible but adds a second source of truth for zero functional gain, and is excluded (Assumption A-3).
10. **MCP `resources` and `prompts` primitives.** Version 1.0 ships `tools` only. Resources are a plausible future fit for vendored specs and console inventories, but adding a second primitive before the tool surface is proven splits the verification effort.
11. **Automatic absorption of vendor spec changes.** Spec bumps land as reviewed pull requests (FR-05). Auto-merging a firmware-versioned spec would let an operation appear in the tool surface with no human ever having read its description.
12. **Guaranteed compatibility with non-Claude MCP clients.** The server speaks standard MCP and will likely work elsewhere, but the payload ceilings, annotation semantics, and confirmation behaviour this PRD optimises for are Claude's. Other hosts are best-effort, untested, and unsupported in 1.0.
13. **Bulk fleet orchestration primitives** (apply-to-all-consoles, scheduled sweeps, cross-console transactions). Marcus will want these. They are a v2 conversation that depends on resolving the Connector rate-limit economics first.

---

## 8. Dependencies & Risks

| # | Dependency / Risk | Type | Owner | Mitigation |
|---|---|---|---|---|
| D-1 | Ubiquiti's developer portal (`developer.ui.com`) serves the four specs and the root `llms.txt` index | Dependency | Repo maintainer | Specs are vendored (FR-01) so runtime never depends on the portal. For refresh, community mirrors `opastorello/unifi-api-docs` (daily CI mirror of all four) and `beezly/unifi-apis` (controller-extracted Network/Protect, currently ahead of the portal) are documented fallbacks; mirror-sourced specs are labelled as such in the refresh PR |
| D-2 | `mcp-server-dev:build-mcp-server` skill performs the implementation pass | Dependency | Repo maintainer | This PRD answers the skill's four discovery questions (ADR-01 … ADR-04) so the skill proceeds directly to recommendation and scaffolding |
| D-3 | MCP Inspector (`@modelcontextprotocol/inspector`) is the verification tool, including `--cli` mode in CI | Dependency | Repo maintainer | Pin the Inspector version in CI; the build skill prescribes Inspector and ships no test scaffolding of its own, so this dependency is load-bearing (see R-7) |
| D-4 | OS keychain access (`keytar`) for credential storage | Dependency | Repo maintainer | Environment-variable fallback for headless and CI (FR-15, NFR-20) |
| R-1 | **Ubiquiti ships breaking-ish changes without advance notice** — new endpoints, new optional parameters, new and reordered response properties, changed length/format of opaque strings. No formal deprecation or sunset policy is published | Risk (High likelihood, High impact) | Repo maintainer | Permissive parsing is an NFR, not a nicety (NFR-11); drift fuzz suite (FR-61); no strict response validation anywhere; opaque identifiers never length- or format-checked. Absence of a deprecation policy is tracked as OQ-03 |
| R-2 | **The Cloud Connector's 100 req/min per console is the binding constraint** on Marcus's fleet use case; a naive 60-console sweep self-rate-limits | Risk (High likelihood, Medium impact) | Repo maintainer | Per-console token bucket (FR-12, NFR-15); fan-out simulation in the test suite; bulk orchestration explicitly out of scope for v1 pending an economics review |
| R-3 | **Self-signed console certificates push users toward globally disabling TLS verification** | Risk (High likelihood, High impact) | Repo maintainer | Explicit, narrowly-scoped, loudly-named opt-in that cannot affect `api.ui.com` (FR-09, NFR-14); CA-bundle path offered first in the error text |
| R-4 | **A model is tricked into calling a state-changing tool.** Tool inputs are untrusted even though they come from an AI the user trusts | Risk (Medium likelihood, Very High impact) | Repo maintainer | Read-only default (FR-44); separate write tool (NFR-01); Never-Ship blocklist for irreversible operations (FR-46); `destructiveHint` on everything that mutates (FR-47) |
| R-5 | **Prompt injection via network-controlled strings** — a hostile SSID, hostname, device name, or camera name reaches the model's context through tool output | Risk (Medium likelihood, High impact) | Repo maintainer | Untrusted-data delimiting and labelling (FR-56); length bounds and control-character neutralisation (FR-57, NFR-21); read-only default limits the blast radius of a successful injection |
| R-6 | **Protect's unpaginated arrays exceed host payload ceilings** on a large installation | Risk (High likelihood, Medium impact) | Repo maintainer | Server-side slicing and projection (FR-37); large-estate fixture as a build gate (FR-51); 150,000-character ceiling as an NFR (NFR-08) |
| R-7 | **The build skill ships no test scaffolding**, so test strategy is a genuine gap this project must fill itself | Risk (Certain, Medium impact) | Repo maintainer | Test strategy is a named M2 deliverable: fixture-driven contract tests per API, a drift fuzz suite, a large-estate fixture, an outbound-request interceptor, and Inspector `--cli` smoke tests in CI (FR-60). Tracked as OQ-10 |
| R-8 | **Network and Protect specs declare no `securitySchemes`**; a generator that trusts the spec emits unauthenticated clients | Risk (Certain, High impact if missed) | Repo maintainer | Documented post-generation auth injection with a self-asserting precondition (FR-06) |
| R-9 | **Mobility's published rate limit is self-contradictory** (spec `info.description` says 100 req/min per key; the Getting Started page says 10,000 req/min; both are live) | Risk (Certain, Low impact) | Repo maintainer + Ubiquiti developer support | Do not hard-code either value. Configurable limit with a conservative provisional default; tracked as OQ-01 |
| R-10 | **Local-mode Network and Protect rate limits are unpublished** | Risk (Certain, Low impact) | Repo maintainer | Conservative configurable default; empirical measurement on the maintainer's own console; tracked as OQ-02 |
| R-11 | **Connector documentation is internally inconsistent** on the `/proxy` path segment | Risk (Certain, Medium impact if wrong) | Repo maintainer | Use the `/proxy/...` form, corroborated by the specs' `servers[]` entries, the path-parameter example, and `ai-gettingstarted.md`; assert it in a unit test; tracked as OQ-06 |
| R-12 | **MCPB distribution requires bundling a runtime and, on some platforms, code signing/notarisation** the maintainer may not have set up | Risk (Medium likelihood, Medium impact) | Repo maintainer | M1–M3 use plain local stdio via `claude mcp add`, which needs no packaging; MCPB packaging is a separate M4 milestone that can slip without blocking function; tracked as OQ-08 |
| R-13 | **Site Manager write endpoints ship mid-development**, invalidating the read-only assumption | Risk (Low likelihood, Low impact) | Repo maintainer | Site Manager is read-only by data (FR-17), not by hard-coding; when write endpoints appear in a refreshed spec, they enter the normal write-gating path. Existing keys will not gain write access automatically; tracked as OQ-04 |
| R-14 | **Solo-maintainer bus factor.** Every owner in this document is the same person | Risk (Certain, Medium impact) | Repo maintainer | Decisions are recorded as ADRs in-repo; the coverage report and spec SHAs are committed artefacts; the build is reproducible from vendored inputs (NFR-22) |

---

## 9. Timeline & Milestones

Relative to PRD acceptance (T+0). No calendar dates are asserted because no delivery date has been stated. Week offsets assume part-time solo effort and are estimates, not commitments.

| Milestone | Target | Exit Criteria |
|---|---|---|
| **M0 — PRD acceptance** | T+0 | This document is reviewed and marked Approved by the repo maintainer. ADR-01 … ADR-04 are accepted as decided. OQ-01, OQ-02, OQ-06, OQ-08, and OQ-12 have named resolution paths and owners. **This is the entry gate for M1.** |
| **M1 — Implementation via `mcp-server-dev:build-mcp-server`** | T+1 week | The `mcp-server-dev:build-mcp-server` skill is invoked with Section 12 ("Handoff to build-mcp-server") as its design brief. Because the four discovery questions are answered here, the skill skips discovery and proceeds to recommendation and scaffolding. Exit: a running local stdio server that responds to `tools/list` with the promoted read tools and `unifi_search_actions`, backed by vendored specs, with zero runtime dependency on `developer.ui.com` (NFR-17). |
| **M2 — Spec ingestion, action registry, and test strategy** | T+3 weeks | All four specs vendored at the pinned versions (FR-01). Refresh routine bootstrapping from `https://developer.ui.com/llms.txt` with OpenAPI-body validation (FR-02, FR-03). Auth injection for Network and Protect verified (FR-06). Coverage check green: 100% of spec operations either registered or blocklisted (FR-59). Test strategy exists as an actual harness — fixture-driven contract tests per API, drift fuzz suite, outbound-request interceptor, large-estate fixture (R-7). |
| **M3 — Read-path complete across all four APIs, all three transports** | T+6 weeks | Normalized pagination and error contracts pass fixture tests for all four APIs (FR-23, FR-24). Cloud-direct, local-direct, and Connector transports all functional with transport chosen by configuration (FR-07–FR-11). Network filter DSL modelled and validated (FR-33). Protect slicing and projection under the payload ceiling against the large-estate fixture (FR-37, FR-51). Mobility scope metadata and 403 path (FR-39, FR-40). **Interactive MCP Inspector session** (`npx @modelcontextprotocol/inspector`) exercises every promoted tool and both execution tools. |
| **M4 — Write path, safety gating, and injection hardening** | T+8 weeks | Read-only default verified by a boot test (FR-44, G-6). `unifi_execute_write_action` separate from the read tool (NFR-01). Never-Ship blocklist published and enforced with all writes enabled (FR-46). Annotations complete and lint-enforced (NFR-02). Mobility 204 handling (FR-41). Untrusted-string delimiting and sanitisation (FR-56, FR-57). Description lint green (NFR-04). |
| **M5 — Distribution: MCPB packaging and 1.0** | T+10 weeks | MCPB bundle builds and installs on macOS, Linux, and Windows (NFR-20), with credential fields marked `sensitive: true` (NFR-13). CI runs MCP Inspector in **`--cli` mode** as a smoke test on every commit and fails the build on a non-zero exit (FR-60). Time-to-first-call walkthrough measured against G-4. All G-1 … G-9 metrics measured and recorded. Version 1.0 tagged. |
| **M6 — Post-launch drift watch** | T+10 to T+22 weeks | Scheduled spec-refresh runs open reviewed PRs on every Ubiquiti version bump (G-8). Zero production breakages attributable to undeclared vendor changes over 90 days (G-7). Open questions OQ-01, OQ-02, OQ-03, and OQ-04 either resolved or formally re-scoped. |

---

## 10. Open Questions

Every CONFLICT and UNVERIFIED item from the source brief is carried here rather than resolved by assertion. Owners are named realistically for a solo greenfield project.

| # | Question | Owner | Resolution path | Due |
|---|---|---|---|---|
| OQ-01 | **CONFLICT — Mobility rate limit.** The Mobility spec's `info.description` states 100 req/min per key; the Getting Started page states 10,000 req/min. Both are currently published. Which governs? | Repo maintainer + Ubiquiti developer support | (1) Open a developer-support ticket citing both published sources. (2) In parallel, measure empirically against a real Mobility-scoped key by ramping request rate until a 429 appears, and record the observed threshold. (3) Until resolved, ship a configurable limit defaulting to the conservative 100 req/min and label the default provisional in the README. Do not hard-code either published figure. | Before M3 |
| OQ-02 | **UNVERIFIED — local-mode Network and Protect rate limits.** Not published anywhere. | Repo maintainer | Empirical measurement against the maintainer's own console: ramp request rate on a read endpoint until throttling or degradation appears, on both a Network and a Protect integration path; record the observed behaviour and whether throttling is server-side at all. Ship a conservative configurable default meanwhile (NFR-15). | Before M3 |
| OQ-03 | **UNVERIFIED — deprecation and sunset policy.** Ubiquiti publishes changes without advance notice and no formal deprecation or sunset policy exists. How much warning does a removed endpoint get? | Repo maintainer + Ubiquiti developer support | Ask developer support directly. Independently, once two vendored spec versions per service exist, diff them for removed operations and measure the observed removal cadence. Until answered, the mitigation is architectural, not procedural: permissive parsing (NFR-11) and reviewed spec bumps (FR-05). | Before M6 |
| OQ-04 | **Site Manager write endpoints.** Ubiquiti's docs state that when write endpoints ship, existing keys will not gain write access automatically and a manual key update will be required. When do they ship, and what does "manual key update" concretely require of a user? | Repo maintainer + Ubiquiti developer support | Monitor the Site Manager spec version in the scheduled refresh (FR-02) for mutating operations appearing. When they do, ask support what the key-update procedure is, and document it before exposing any Site Manager write action. | Deferred — triggered by spec change |
| OQ-05 | **`X-API-Key` header casing.** Ubiquiti's own documentation varies the casing across pages. HTTP headers are case-insensitive by specification, so this is almost certainly cosmetic — but "almost certainly" is not verified against every gateway in the path, particularly the Cloud Connector. | Repo maintainer | Send `X-API-Key` (the canonical form) and add a smoke test per API and per transport asserting a 200. If any path rejects it, capture the exact casing that path accepts and record it. Low risk; cheap to verify at M3. | Before M3 |
| OQ-06 | **Connector path form.** The Cloud Connector's own description shows example paths *without* `/proxy`, while the `servers[]` entries in the Network and Protect specs, the path-parameter example, and `ai-gettingstarted.md` all include it. The `/proxy/...` form is used (FR-10) on the weight of three corroborating sources against one — but the inconsistency is unresolved at the vendor. | Repo maintainer + Ubiquiti developer support | Verify empirically against a real console through the Connector at M3; both forms are cheap to test. Report the documentation inconsistency to developer support regardless of which works, so it gets fixed upstream. If both forms work, keep `/proxy` and note the alternative. | Before M3 |
| OQ-07 | **Protect spec `info.version` is `"0.0.0"`** — a stub. The URL version segment (`v7.1.87`) is authoritative and is what the product uses (FR-35). Will Ubiquiti fix the stub, and if they do, could the fixed value ever disagree with the URL segment? | Repo maintainer | Assert in the ingestion pipeline that Protect's `info.version` is either `0.0.0` or exactly matches the URL segment; fail the refresh loudly on any third value so a human looks at it. Report the stub to developer support. | Before M2 |
| OQ-08 | **MCPB packaging feasibility.** ADR-01 selects local deployment with MCPB as the distribution format. Bundling a Node runtime for three platforms may require code signing or notarisation the maintainer has not set up, and `keytar` is a native module with platform build implications. | Repo maintainer | Spike at M4: build an MCPB bundle for each target platform and install it on a clean machine. If signing proves to be a blocker on any platform, that platform ships as plain local stdio via `claude mcp add` (which needs no packaging) and MCPB is deferred for it. This is a distribution-convenience question, not a functional one — it cannot block M1–M4. | Before M5 |
| OQ-09 | **Remote HTTP deployment for cloud-only users.** Priya's persona (Site Manager and Mobility only, no local console) is fully served by cloud-reachable APIs and would work as a remote streamable-HTTP server — the build skill's default. It is excluded in v1 solely because the auth mechanism does not exist (ADR-01). Is a single-tenant self-hosted remote deployment worth shipping for that segment? | Repo maintainer | Defer until v1 ships and usage shows whether cloud-only users are a meaningful share. If Ubiquiti publishes OAuth, this reopens immediately with a much better answer. The architecture keeps the transport layer separable specifically so this stays cheap (ADR-01 Implications). | Post-1.0 |
| OQ-10 | **Test strategy is an acknowledged gap.** `mcp-server-dev:build-mcp-server` prescribes MCP Inspector for verification and ships no test scaffolding of its own. What is the unit- and contract-test layer beneath Inspector? | Repo maintainer | Specified as an M2 deliverable rather than left implicit: fixture-driven contract tests per API using recorded real responses, a drift fuzz suite (FR-61), an outbound-request interceptor asserting the read-only default (FR-44), a large-estate fixture (FR-51), and Inspector `--cli` in CI (FR-60). The open part is whether recorded fixtures alone suffice or a live-console integration suite is needed; decide at M2 once fixture fidelity is observable. | Before M2 |
| OQ-11 | **Never-Ship blocklist membership needs sign-off.** FR-46 proposes blocking adoption/un-adoption, firmware upgrade, factory reset, reboot/power-cycle, and site/network/WLAN deletion. Client block is gated rather than blocked because it is reversible. Is that the right line? | Repo maintainer | Review the proposed list against the actual mutating operations enumerated from the vendored specs at M2, when the real inventory is known rather than assumed. Each entry needs a one-line reason in the blocklist file. Ratify at M4 before the write path ships. | Before M4 |
| OQ-12 | **Operation counts are approximate.** The four specs total "roughly 200+ operations" per the brief; the exact count per service is not established, and G-1 is deliberately written as a percentage against a build-time-computed denominator rather than against a guessed absolute. | Repo maintainer | Compute exact per-service counts during M2 spec ingestion and record them in the committed coverage report (FR-59). This does not change G-1's target; it makes the metric concrete. | Before M2 |
| OQ-13 | **Organization-key behaviour across consoles is documented but unverified.** Non-organization keys reach only the key owner's consoles; organization keys reach any console in the org. Marcus's entire use case rests on the second half. | Repo maintainer | Verify at M3 with an organization key against at least two consoles owned by different accounts within one org, and with a non-organization key against a console the key owner does not own (expecting a clean, well-named denial). Record the actual error shape for FR-53's recovery hint. | Before M3 |
| OQ-14 | **Community mirror licensing and trust.** `opastorello/unifi-api-docs` and `beezly/unifi-apis` are the documented fallbacks when the portal is unreachable, and `beezly/unifi-apis` is currently *ahead* of the portal (controller-extracted). Is it acceptable to vendor a spec sourced from a mirror rather than from Ubiquiti? | Repo maintainer | Policy decision, not a technical one. Proposed policy: mirrors are acceptable for *diffing and early warning*, and a mirror-sourced spec may be vendored only when the refresh PR labels its provenance explicitly and a human approves. Never auto-vendor from a mirror. Ratify at M2. | Before M2 |
| OQ-15 | **Headless keychain availability.** NFR-20 requires headless Linux support with an environment-variable fallback. Does that fallback create an unacceptable plaintext-in-environment exposure for the CI use case? | Repo maintainer | Document the trade-off explicitly in the README rather than silently accepting it: keychain is the supported path; environment variables are for CI and headless use where the operator already controls secret injection. Revisit if a credential-helper interface proves cheap to add. | Before M5 |

---

## 11. Architecture Decisions

These four decisions are **DECIDED**, not proposed. They exist so that `mcp-server-dev:build-mcp-server` skips its discovery phase. Residual uncertainty has been pushed into Section 10 (Open Questions) and does not reopen these decisions.

---

### ADR-01 — Deployment model: **local server (stdio), distributed as MCPB**

**Date:** 2026-08-01 · **Decision Maker:** Repo maintainer · **Status:** Decided

#### Context

The `mcp-server-dev:build-mcp-server` skill's default is emphatic: *"Remote streamable-HTTP… This is the recommended path for anything wrapping a cloud API. Choose this unless the server must touch the user's local machine."* MCPB is *"when the server must run on the user's machine — it reads local files, drives a desktop app, talks to localhost services, or needs OS-level access."* Local stdio is *"not recommended for distribution… Fine for personal tools and prototypes."*

UniFi splits down the middle of that rule, which is why this cannot be inherited as a default:

- **Site Manager and Mobility** are cloud APIs on `api.ui.com`. Textbook remote HTTP.
- **Network and Protect via Cloud Connector** are reachable from anywhere through `api.ui.com`. Remote HTTP works.
- **Network and Protect in local-direct mode are on the user's LAN at a private address.** A remote HTTP server cannot reach `192.168.x.x`. This is not a preference; it is routing.

Auth compounds it. UniFi uses a long-lived, user-supplied API key created at `unifi.ui.com` or on the local console, shown once. The build skill states Claude does not support *"user-pasted bearer tokens (`static_bearer`)"*, and Ubiquiti publishes no OAuth. A hosted multi-tenant remote server would need each user's UniFi key with **no supported mechanism to collect it**. That is not a difficulty to engineer around; it is a missing primitive.

#### Options Considered

**Option A: Remote streamable-HTTP covering cloud + Connector only; local-direct declared out of scope**
- Pros: The skill's recommended default. No distribution problem — users add a URL. Centralised updates. Serves Priya and most of Marcus.
- Cons: **Abandons Dana entirely**, the primary persona. Local-direct is not a niche: it is how every single-console owner with the controller on their own LAN actually operates, and it is the only mode with no rate limit and no 25-second timeout. And the auth primitive does not exist — a hosted deployment has no supported way to collect a user's UniFi key. This option is blocked on two independent grounds, either of which alone would sink it.

**Option B: Local stdio only, no packaging**
- Pros: Simplest. Reaches everything — LAN and cloud alike. No auth-collection problem: the key is in the user's own keychain. Zero infrastructure.
- Cons: The skill calls plain stdio *"not recommended for distribution."* Requires the user to have a runtime installed and to hand-edit MCP configuration. Fine for the maintainer, poor for Dana.

**Option C: Local server distributed as MCPB** *(chosen)*
- Pros: Reaches the LAN, which is the hard requirement. Bundles the runtime, so Dana installs one file. MCPB manifests support configuration fields marked `sensitive: true`, which is exactly the credential surface needed (NFR-13). Keychain access is available because the process runs as the user. Serves all four personas from one artifact.
- Cons: Distribution work — bundling, and possibly code signing per platform (OQ-08). Updates ship as new bundles rather than server-side. Does not serve a browser-only user with no machine to install on.

**Option D: Both shapes from one codebase, transport chosen by configuration**
- Pros: Theoretically serves everyone. The core (spec ingestion, action registry, normalization, safety gating) is genuinely transport-agnostic.
- Cons: **Doubles the verification surface at exactly the moment there is no test scaffolding** (R-7), for a remote half that still cannot collect credentials (the Option A blocker, unchanged). Two deployment models means two security models, two configuration stories, two sets of documentation, and two things to get wrong — before either is proven.

#### Decision

**Ship a local server on stdio transport, distributed as an MCPB bundle.** Plain local stdio via `claude mcp add` is the development and early-adopter path (M1–M4); MCPB packaging is the distribution format at M5.

The answer is "local, for now," and this document says so plainly rather than pretending remote was chosen. The local-direct requirement is a routing fact that no amount of architecture removes, and the credential-collection gap makes hosted remote unavailable rather than merely inadvisable. The build skill's own MCPB criterion — *"talks to localhost services"* — is satisfied in substance: the server talks to a service on the user's LAN that no external host can reach.

**Option D is explicitly rejected for v1** and explicitly preserved as a v2 path: the codebase keeps HTTP-client, credential-resolution, and transport-selection concerns separable so that adding a remote entrypoint later is an addition, not a rewrite. It is not built now because building it now buys nothing that works.

#### Implications

- Local-direct, cloud-direct, and Connector transports are all in scope from one artifact (FR-07–FR-11).
- Credentials live in the OS keychain with an environment-variable fallback (FR-15, NFR-13). This is available *because* the server is local — it is a benefit of the choice, not a workaround.
- Distribution cost is real and owned: MCPB bundling and possible signing (OQ-08, R-12). It is scheduled at M5 and cannot block M1–M4.
- Ruled out for v1: any hosted multi-tenant deployment (Out of Scope #6); any browser-only usage.
- The skill's **MCPB upgrade path** is the stated route from prototype to distribution, and it is on the timeline rather than aspirational.
- If Ubiquiti publishes OAuth, OQ-09 reopens this decision with materially better inputs.

#### Review Date

Reopen when either (a) Ubiquiti publishes an OAuth flow for developer API access, or (b) post-1.0 usage shows cloud-only users are the dominant segment — whichever comes first.

---

### ADR-02 — Tool pattern: **hybrid — 5 promoted read tools + search/execute**

**Date:** 2026-08-01 · **Decision Maker:** Repo maintainer · **Status:** Decided

#### Context

The build skill's thresholds: 1–15 operations → one tool per action ("sweet spot"); 15–30 → "still workable, audit for near-duplicates"; **30+ → "switch to search + execute"**. It also offers a hybrid: *"Promote the 3–5 most-used actions to dedicated tools, keep the long tail behind search/execute."*

The rationale is context economics, not a protocol limit: *"Every tool schema is tokens Claude spends every turn. Thirty tools with rich schemas can eat 3–5k tokens before the conversation even starts."* And: *"listing every operation as a tool floods the context window and degrades model performance."*

Four UniFi specs total roughly 200+ operations (exact counts at OQ-12). That is not near the 30 threshold — it is nearly an order of magnitude past it.

#### Options Considered

**Option A: One tool per operation**
- Pros: Every operation directly discoverable in `tools/list`. No search round-trip. Richest static schemas.
- Cons: 200+ tools. Well over 25,000 tokens of schema before a single message is exchanged, against a Claude Code payload budget of roughly 25,000 tokens *total*. This does not degrade performance; it consumes the context window outright. Not viable at any size of estate.

**Option B: Pure search + execute**
- Pros: Minimal, fixed context cost regardless of how many operations exist — the pattern the skill prescribes above 30. Scales to future APIs (Access, Talk) with no schema growth.
- Cons: Every interaction pays a search round-trip, including the ones every user makes first. "List my sites" becoming two tool calls is a poor first impression and a measurable latency cost on the most common path.

**Option C: Hybrid — promote the highest-traffic reads, long tail behind search/execute** *(chosen)*
- Pros: The skill's own recommended refinement. Common questions answer in one call; the long tail stays free. Promoted tools double as the discovery entry points a new user needs before they know anything about their own estate.
- Cons: Two mental models. Requires defending which operations get promoted, and re-defending it as usage data arrives.

#### Decision

**Hybrid.** Exactly **five** operations are promoted to dedicated tools, plus `unifi_search_actions`, plus **two** execution tools (`unifi_execute_action` for reads, `unifi_execute_write_action` for writes — separate because NFR-01 requires it and directory review auto-rejects a combined tool).

The five promotions, each argued rather than assumed:

1. **`unifi_list_consoles`** (Site Manager). Promoted because it is the **discovery primitive for the entire Connector transport**. Marcus cannot construct a single Connector request without a `consoleId`, and there is no other way to obtain one (FR-53). A user who must first search for the tool that tells them what their consoles are called has been failed at step zero. It also returns firmware versions, which determine Connector eligibility (≥ 5.0.3) — so one call answers both "what can I address" and "what can I reach".
2. **`unifi_list_sites`** (Site Manager). Promoted because a site identifier is an **argument to most Network operations**. It sits on the critical path of nearly every Network question, so making it a search round-trip taxes the majority of interactions. It is also the natural first call for a cloud-only user (Priya) who has nothing else configured.
3. **`unifi_list_devices`** (Network). Promoted on **traffic**: "what's on my network / what's offline / what firmware is my AP on" is the single most common class of question this product exists to answer. It is also the entry point for device-scoped follow-ups, so it appears early in most multi-turn sequences.
4. **`unifi_list_clients`** (Network). Promoted on **traffic and distinctness**. It is the second most common question class and — critically — it is the tool most easily confused with `unifi_list_devices`. Promoting both, with descriptions that name each other as near-siblings (NFR-03), disambiguates them structurally. Left in the search tail, a search for "what's connected" would surface both and the disambiguation burden would fall on the model every time.
5. **`unifi_list_cameras`** (Protect). Promoted because it is the **only Protect entry point** and because Protect is the API most in need of a shaped tool: it has no pagination at all and returns full arrays (FR-36, FR-37). A generic `execute_action` over a Protect list endpoint has nowhere natural to put slicing and projection defaults. Promoting it makes the bounded, projected shape the default rather than an option a caller has to know to request.

Rejected for promotion despite being plausible: Mobility device listing (Sam is a secondary persona and the smallest spec; the extra schema cost is not repaid by traffic), and any write operation (writes are absent by default, so promoting one would advertise a tool that usually is not there).

**Tool exposure is filterable by configuration.** Each API is independently enableable (FR-22). A user who owns no Protect gear does not pay for Protect schemas — and given that the entire justification for this pattern is token cost, charging a Protect-free user for Protect schemas would contradict the decision.

#### Implications

- `tools/list` returns at most 12 tools with all four APIs enabled (FR-18), against a budget of 3,000 tokens (G-3, NFR-18).
- `unifi_search_actions` must return directly-usable action IDs and their schemas (FR-19) — if the search result needs interpretation, the pattern fails.
- Ruled out: adding a sixth promoted tool without a corresponding token-budget measurement. Promotions are a budgeted resource, not a convenience.
- The action registry becomes the central data structure: it carries every operation's ID, schema, service, read/write class, scope requirements, and rate-limit bucket.
- Adding a fifth API later costs approximately zero schema tokens for its long tail.

#### Review Date

Reconsider the promotion set after 90 days of real usage (M6), on evidence of which actions are actually executed most.

---

### ADR-03 — Framework: **official TypeScript SDK (`@modelcontextprotocol/sdk`)**

**Date:** 2026-08-01 · **Decision Maker:** Repo maintainer · **Status:** Decided

#### Context

The build skill recommends exactly two frameworks and has a default: **the official TypeScript SDK (`@modelcontextprotocol/sdk`) is the default choice** — *"best spec coverage, first to get new features."* **FastMCP 3.x** (jlowin's PyPI package, not the frozen FastMCP 1.0 inside the official `mcp` SDK) is the Python alternative — *"user prefers Python, or wrapping a Python library."* It adds: *"If the user already has a language/stack in mind, go with it — both produce identical wire protocol."*

The repository is greenfield with one commit and no stated language preference, so the tiebreaker must come from the workload: an HTTP client, OpenAPI schema handling across 3.0.3 and 3.1.0 documents, and — because ADR-01 chose MCPB — runtime bundling.

#### Options Considered

**Option A: Official TypeScript SDK** *(chosen)*
- Pros: The skill's stated default, with best spec coverage and first access to new MCP features — which matters for a server leaning on `outputSchema`/`structuredContent` (NFR-09) and on annotation semantics (NFR-02). **MCPB bundling is a Node story first**: the `mcpb` tooling and Node runtime bundling are the well-trodden path, and ADR-01 makes bundling a shipping requirement, not a nice-to-have. `keytar` is the credential-storage module the skill names for local servers (NFR-13). OpenAPI 3.1 is JSON Schema 2020-12, which lands natively in the TypeScript/zod/ajv ecosystem with no impedance mismatch. Generating TypeScript types from the vendored specs gives compile-time checking over an action registry built from four large documents. `fetch`/`undici` covers the HTTP needs including per-host TLS configuration for the self-signed-certificate case (FR-09).
- Cons: OpenAPI-to-client codegen in TypeScript is a crowded field with no single obvious winner, so tool selection needs a small spike. Native modules (`keytar`) complicate cross-platform bundling (OQ-08) — though this cost exists in Python too.

**Option B: FastMCP 3.x (Python)**
- Pros: Ergonomic decorators; excellent OpenAPI tooling; `keyring` is a mature credential library; strong for anyone more fluent in Python.
- Cons: The skill's stated triggers for choosing it — *"user prefers Python, or wrapping a Python library"* — are **both absent here**. There is no stated preference and no Python library being wrapped; UniFi is reached over plain HTTPS. Bundling a Python runtime into an MCPB for three platforms is heavier and less trodden than the Node path, and ADR-01 makes that cost load-bearing. Choosing it would mean overriding the skill's default with no reason drawn from the workload.

**Option C: a third language (Go, Rust)**
- Pros: Single static binary would genuinely simplify distribution, which is the main cost of ADR-01.
- Cons: The skill recommends exactly two frameworks, and a third would need an argument that **both** recommended options fail. Neither fails: TypeScript covers the workload cleanly. Going outside the recommendation costs first-class MCP SDK support, the MCPB tooling path, and the skill's own scaffolding — to save packaging effort that MCPB already solves. Not justified.

#### Decision

**Official TypeScript SDK (`@modelcontextprotocol/sdk`) on Node.**

The decisive factor is not language preference — there is none to honour — but that the MCPB requirement from ADR-01 and the schema-handling workload both point the same way, and they point at the skill's default. Choosing the default when the workload independently agrees with it is the cheapest correct decision available.

#### Implications

- Credential storage uses `keytar` (NFR-13); the environment-variable fallback covers headless Linux where no keychain daemon exists (NFR-20, OQ-15).
- Spec ingestion produces TypeScript types and a typed action registry from the vendored JSON specs, deterministically (NFR-22).
- MCPB bundling follows the Node path at M5; the native `keytar` dependency is the specific risk to spike (OQ-08).
- Ruled out: Python and any third language for v1. Reopening requires a workload fact that changes, not a preference.
- All diagnostics go to stderr, because stdio transport owns stdout (NFR-19).

#### Review Date

Not scheduled. Revisit only if MCPB Node bundling proves unworkable on a required platform (OQ-08), in which case distribution — not framework — is what changes.

---

### ADR-04 — Auth: **user-supplied API keys in the OS keychain, multi-credential by target, never in the transcript**

**Date:** 2026-08-01 · **Decision Maker:** Repo maintainer · **Status:** Decided

#### Context

All four UniFi APIs authenticate with a long-lived API key in an HTTP header (`X-API-Key`; casing varies across Ubiquiti's own docs, and HTTP headers are case-insensitive — OQ-05). Keys are created at `https://unifi.ui.com` → Settings → API Keys for cloud use, or on the local console under Integrations, and are **shown once at creation**.

Complications the design must absorb:

- **Network and Protect specs declare no `securitySchemes` and no `security` block at all.** A generator that trusts the spec emits unauthenticated clients (FR-06, R-8).
- **Mobility needs a `mobility` app scope** on the key (403 without it), plus `read:mobility` for GETs and `write:mobility` for PUTs; the caller needs workspace Admin, and writes need an active cloud subscription on the target device.
- **Site Manager keys are read-only today**, and when write endpoints ship, existing keys will not gain write access automatically.
- **A user may legitimately hold two or more keys**: a cloud key from `unifi.ui.com` (serving Site Manager, Mobility, and all Connector traffic) and one or more local console keys created on each console's Integrations page.

Skill constraints that bind: for local/MCPB servers, tokens belong in the **OS keychain** (`keytar`/`keyring`) — *"Never plaintext on disk"*; MCPB manifests mark such fields `sensitive: true`; *"Tool results flow into the chat transcript. Anything you return, the user (and any log export) can see. Redact before returning."* And elicitation **must not** be used to collect API keys.

#### Options Considered

**Option A: Single key, one credential for everything**
- Pros: Simplest possible configuration and documentation.
- Cons: Factually wrong. A cloud key does not authenticate to a local console's integration endpoint, and a local console key does not authenticate to `api.ui.com`. Dana with a local console and Priya with a cloud key are not the same configuration, and a user who is both is not exotic. This option cannot express local-direct plus cloud simultaneously.

**Option B: Keychain-first, multi-credential, resolved by target** *(chosen)*
- Pros: Models reality: one cloud key plus zero or more host-bound local keys, resolved per request by which target the operation routes to (FR-14). Keychain storage satisfies the never-plaintext constraint. Environment-variable fallback keeps CI and headless Linux working. MCPB `sensitive: true` handles the install-time input path without elicitation.
- Cons: More configuration surface, and a harder error-message job — "which key was even used?" must be answerable without printing any key.

**Option C: Plaintext config file**
- Pros: Trivially portable, easy to inspect and version.
- Cons: Directly violates *"Never plaintext on disk."* Rejected outright.

**Option D: Prompt the user for the key through elicitation**
- Pros: Smooth in-chat onboarding.
- Cons: Explicitly prohibited — elicitation must not be used to collect API keys. Rejected outright.

#### Decision

**Option B.** Specifically:

- **How the key reaches the server:** at install/configure time, via MCPB manifest configuration fields marked `sensitive: true`, or via environment variables for development, CI, and headless use. Never via elicitation. Never via a tool argument.
- **Where it rests:** the OS keychain via `keytar`, with an environment-variable fallback when no keychain is available; a stderr notice states which path is in use (FR-15). The server writes no plaintext credential file, ever (NFR-13).
- **Multiple keys:** one **cloud key** used for Site Manager, Mobility, and all Cloud Connector traffic; zero or more **local console keys**, each bound to a configured console host. Credential selection is derived from the resolved request target, never from a caller-supplied argument (FR-14). A local-direct request to a host with no bound credential fails with a structured error naming the host and the exact configuration key required — and naming no key material.
- **Scopes as data:** Mobility scope requirements (`mobility` app scope, `read:mobility`, `write:mobility`) are recorded in action metadata and surfaced in descriptions and in the 403 recovery hint (FR-39, FR-40). Site Manager's read-only status is likewise data, not a hard-coded branch, so the eventual arrival of write endpoints is a spec change rather than a code change (FR-17).
- **Auth injection:** because the Network and Protect specs declare no security scheme, the ingestion pipeline injects the header requirement for those services in a documented post-generation step that asserts its own precondition (FR-06).
- **Never in the transcript:** key values never appear in tool results, `structuredContent`, error messages, or logs. Enforced by an automated scan for a planted sentinel value across every output channel (NFR-12).

#### Implications

- Configuration validation must catch enabled-API-without-credential at startup and name it (FR-54), rather than surfacing it as a confusing 401 at first call.
- Error messages must be diagnosable without revealing key material: they name the *target* and the *configuration key*, never the value.
- Server introspection reports effective configuration with secrets redacted, verified by sentinel test (FR-55).
- Ruled out: any credential path through elicitation, any plaintext credential file, any tool argument that accepts a key.
- Headless environments accept environment-variable storage as a documented trade-off rather than a silent one (OQ-15).

#### Review Date

Reopen if Ubiquiti publishes OAuth, which would change both this decision and ADR-01.

---

## 12. Handoff to `mcp-server-dev:build-mcp-server`

*This paragraph is the design brief. The skill's discovery phase asks for four decisions before it will scaffold; all four are settled below, so proceed directly to the recommendation and scaffolding steps.*

**UniFi MCP is a local server on stdio transport, distributed as an MCPB bundle** — local rather than remote streamable-HTTP because Network and Protect in local-direct mode sit at private LAN addresses that no hosted server can route to, and because UniFi's auth is a long-lived user-supplied API key with no OAuth and no supported `static_bearer` collection path, so a hosted multi-tenant deployment has no way to obtain a user's credential; the codebase keeps the transport layer separable so a remote entrypoint for cloud-and-Connector-only use remains an addition rather than a rewrite. **The tool pattern is hybrid search + execute**, because the four vendored OpenAPI specs total roughly 200+ operations — nearly an order of magnitude past the 30-operation threshold at which one-tool-per-action is prohibited — with exactly five operations promoted to dedicated read tools (`unifi_list_consoles`, `unifi_list_sites`, `unifi_list_devices`, `unifi_list_clients`, `unifi_list_cameras`), a `unifi_search_actions` tool mapping natural-language intent to directly-usable action IDs and schemas, and **two** separate execution tools — `unifi_execute_action` for reads and `unifi_execute_write_action` for state-changing operations, separate because a single tool accepting both is auto-rejected at directory review — all under a ≤ 3,000-token advertised-schema budget with per-API exposure filtering so a user without Protect gear pays nothing for Protect schemas. **The framework is the official TypeScript SDK (`@modelcontextprotocol/sdk`) on Node**, the skill's default, chosen because the MCPB bundling requirement is a Node-first path, `keytar` is the named credential-storage module for local servers, and OpenAPI 3.1's JSON Schema 2020-12 lands natively in the TypeScript ecosystem — with no Python library to wrap and no stated language preference, neither of FastMCP's stated triggers applies. **Auth is user-supplied UniFi API keys sent as `X-API-Key`, entered at install time through MCPB manifest fields marked `sensitive: true` or through environment variables, resting in the OS keychain via `keytar` with an environment-variable fallback for headless and CI use and never in plaintext on disk, never collected via elicitation, and never present in any tool result, `structuredContent`, error message, or log** — with multi-credential resolution by request target (one cloud key for Site Manager, Mobility, and all Cloud Connector traffic; zero or more local console keys each bound to a configured host), a documented post-generation auth-injection step for Network and Protect because their specs declare no `securitySchemes` at all, Mobility's `mobility` app scope plus `read:mobility`/`write:mobility` carried as action metadata surfaced in the 403 recovery hint, and a read-only default posture in which `unifi_execute_write_action` is absent from `tools/list` until an explicit configuration flag is set, with an enforced Never-Ship blocklist for irreversible operations (adoption/un-adoption, firmware upgrade, factory reset, reboot/power-cycle, and site/network/WLAN deletion) that are not exposed in any configuration.

Section 6 (NFR-01 … NFR-10) restates the skill's non-negotiable constraints as separately testable requirements; treat that table as the acceptance checklist for the scaffolded server. Section 5 is the functional specification. Verification uses MCP Inspector (`npx @modelcontextprotocol/inspector`, and `--cli` in CI) per FR-60 — no bespoke MCP harness.

---

## 13. Assumptions

Stated explicitly because each one, if wrong, changes something in this document.

- **A-1.** The technical facts in `docs/prd-brief.md` were verified against `developer.ui.com` on 2026-08-01 and are treated as given. Items marked CONFLICT or UNVERIFIED are carried to Open Questions rather than resolved (OQ-01, OQ-02, OQ-03).
- **A-2.** The pinned spec versions — Site Manager `v1.0.0`, Network `v10.4.57`, Protect `v7.1.87`, Mobility `v1.0.0` — are current as of 2026-08-01. Network and Protect version their specs to controller firmware and will drift; the refresh routine exists precisely because of that (FR-02).
- **A-3.** Specs are served as **JSON only**; no YAML variant is published on the portal. A local JSON→YAML conversion is possible but is excluded (Out of Scope #9) because it creates a second source of truth for no functional gain. If a downstream tool ever requires YAML, it is a local build step, never a download.
- **A-4.** The `/proxy/...` Cloud Connector path form is correct, on the weight of the specs' `servers[]` entries, the path-parameter example, and `ai-gettingstarted.md` against the connector description's contradicting examples. Empirical verification is scheduled (OQ-06).
- **A-5.** Roughly 200+ operations exist across the four specs. Exact per-service counts are computed at M2 (OQ-12). G-1 is written as a percentage against a build-time denominator specifically so this assumption cannot corrupt the metric.
- **A-6.** The maintainer has, or can obtain, at least one real console for local-direct testing and at least one Connector-reachable console. Without both, M3's transport verification cannot complete. Organization-key testing across multiple consoles (OQ-13) may require access the maintainer does not have; if so, that verification is deferred and the Marcus persona's Connector path ships as documented-but-unverified, and the README says so.
- **A-7.** A real Mobility-scoped key with an active cloud subscription is obtainable for testing FR-39 through FR-43. If it is not, Mobility ships fixture-verified only, and that limitation is stated in the README rather than glossed.
- **A-8.** Claude Code and Claude Desktop are the target hosts. Payload ceilings (~150,000 characters; ~25,000 tokens) and annotation-driven confirmation behaviour are calibrated to them (NFR-08). Other MCP clients are best-effort (Out of Scope #12).
- **A-9.** Effort estimates in Section 9 assume part-time solo work. They are estimates, not commitments, and no external delivery date has been stated.
- **A-10.** Community mirrors remain available as portal fallbacks. Their vendoring policy is unratified (OQ-14); until it is, mirrors are used for diffing and early warning only.

---

## 14. Next Steps

1. **Review and accept this PRD** (M0). Specifically ratify ADR-01 through ADR-04 as decided, and confirm the Never-Ship blocklist line drawn in FR-46 — that reboot, adoption, firmware upgrade, factory reset, and destructive deletions are not shipped at all, while client block/unblock is gated rather than blocked because it is reversible. *Owner: repo maintainer. Blocks everything else.*
2. **Open the Ubiquiti developer-support items** that have long lead times, in parallel with build work rather than after it: the Mobility rate-limit conflict (OQ-01), the absent deprecation policy (OQ-03), the Connector `/proxy` documentation inconsistency (OQ-06), and the Protect `info.version: "0.0.0"` stub (OQ-07). *Owner: repo maintainer.*
3. **Invoke `mcp-server-dev:build-mcp-server`** with Section 12 as the design brief (M1). The skill's four discovery questions are answered, so it should acknowledge that and proceed directly to recommendation and scaffolding. *Owner: repo maintainer.*
4. **Vendor the four specs at their pinned versions and build the coverage check first** (M2), before any tool work. The coverage report is what turns "cover all four APIs" from an aspiration into a build gate, and it produces the exact operation counts that OQ-12 needs. *Owner: repo maintainer.*
5. **Stand up the test strategy as an explicit M2 deliverable** rather than discovering its absence at M4 (R-7, OQ-10): fixture-driven contract tests per API, the drift fuzz suite, the outbound-request interceptor that enforces the read-only default, the large-estate fixture, and Inspector `--cli` in CI. The build skill ships no test scaffolding; this gap is the project's to fill.
6. **Acquire test access** for the paths that cannot be fixture-verified: a local console with a self-signed certificate, a Connector-reachable console, an organization key spanning at least two consoles, and a Mobility-scoped key with an active subscription (A-6, A-7, OQ-13). Identify gaps now so the README can state them honestly at 1.0 rather than implying coverage that was never exercised.
7. **Spike MCPB bundling early** (OQ-08, R-12), before M5, so that a platform-specific signing or native-module blocker surfaces while it is still cheap to route around. M1–M4 run on plain local stdio and are unaffected either way.

---

*End of document.*
