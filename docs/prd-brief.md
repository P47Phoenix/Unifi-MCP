Role: product_owner | Task: prd

Write a PRD for **UniFi MCP** — a Model Context Protocol server that exposes all four published Ubiquiti UniFi developer APIs (Site Manager, Network, Protect, Mobility) as MCP tools to an LLM client.

Write the artifact to `docs/prd.md` in the repo at `/var/home/meconnelly/Documents/GitHub/Unifi-MCP`. The repo is greenfield: one commit, a `README.md` containing only `# Unifi MCP`, and a stock `.gitattributes`. No language, framework, or scaffolding chosen yet — treat toolchain selection as an open question with a recommendation, not a settled fact.

## Product context

**Who it's for:** a network/home-lab operator who already administers UniFi gear and wants to query and operate it conversationally through an MCP client (Claude Code, Claude Desktop). Today they either click through the UniFi console or hand-roll `curl` against four APIs with three different pagination schemes and three different error envelopes.

**Core value:** one credential, one server, one consistent tool surface over all four APIs — including reaching on-premises Network and Protect controllers through the cloud without a VPN.

**Scope of coverage:** all four APIs. Not a subset. The PRD must state a coverage target and how coverage is measured against the OpenAPI specs.

## Verified technical facts

These were confirmed against developer.ui.com on 2026-08-01. Treat them as given; do not re-derive them. Where a fact is marked CONFLICT or UNVERIFIED, surface it in Open Questions rather than picking an answer silently.

### The four APIs and their specs

| API | Version | OpenAPI spec URL | Spec version |
|---|---|---|---|
| Site Manager | v1.0.0 | `https://developer.ui.com/site-manager/v1.0.0/openapi.json` | 3.0.3 |
| Network | v10.4.57 | `https://developer.ui.com/network/v10.4.57/openapi.json` | 3.1.0 |
| Protect | v7.1.87 | `https://developer.ui.com/protect/v7.1.87/openapi.json` | 3.1.0 |
| Mobility | v1.0.0 | `https://developer.ui.com/mobility/v1.0.0/openapi.json` | 3.0.3 |

- Specs are served as **JSON only**. No YAML variant is published anywhere on the portal. If YAML is wanted in-repo, it is a local conversion step, not a download.
- URL pattern is generic: `https://developer.ui.com/{service}/{version}/openapi.json`. The version segment **must be pinned** — `latest` returns the docs SPA HTML shell with a 200 status, not a spec. Any fetch step must validate that the response body actually parses as an OpenAPI document.
- Network and Protect version their specs to **controller firmware** (10.4.57, 7.1.87), and older versions remain fetchable (e.g. `network/v9.1.120/openapi.json`). Users on older firmware need a way to pin a matching spec version.
- Protect's spec reports `info.version: "0.0.0"` — a stub. The URL version is authoritative.
- Companion resources at the same URL pattern: `postman-collection.json`, `llms.txt` (per-service flattened endpoint list), and `ai-gettingstarted.md`. The root `https://developer.ui.com/llms.txt` indexes all four services, their current versions, and every spec URL — the natural bootstrap/discovery source for a spec-refresh routine.
- Community mirrors exist as a fallback if the portal is unreachable: `opastorello/unifi-api-docs` (daily CI mirror of all four) and `beezly/unifi-apis` (controller-extracted Network/Protect specs, currently ahead of the portal).

### Authentication

- All four APIs authenticate with an API key in an HTTP header. Send `X-API-Key` (case varies across Ubiquiti's own docs; HTTP headers are case-insensitive).
- Keys are created at `https://unifi.ui.com` → Settings → API Keys (cloud), or on the local console under Integrations. Shown once at creation.
- **The Network and Protect specs declare no `securitySchemes` and no `security` block at all.** A generator that trusts the spec will emit unauthenticated clients. The server must inject the auth header itself for these two.
- Mobility additionally requires a `mobility` app scope on the key (403 without it), plus `read:mobility` for GETs and `write:mobility` for PUTs. Caller needs workspace Admin; writes need an active cloud subscription on the target device. Mobility also accepts an optional client-supplied `X-Request-ID` trace header.
- Site Manager keys are currently **read-only**. Ubiquiti's docs state that when write endpoints ship, existing keys will not gain write access automatically — a manual key update will be required.

### Transport topology — three modes

1. **Cloud direct** — Site Manager (`https://api.ui.com`) and Mobility (`https://api.ui.com/v1/mobility`). Public TLS, no host configuration.
2. **Local direct** — Network at `https://{host}/proxy/network/integration` and Protect at `https://{host}/proxy/protect/integration`. Host is user-supplied. **UniFi consoles ship self-signed TLS certificates**, so this mode requires an explicit opt-in TLS-verification bypass and/or a custom CA bundle option. Defaulting to insecure is not acceptable; the PRD should require an explicit, clearly-named opt-in.
3. **Cloud Connector proxy** — reach on-prem Network/Protect through `api.ui.com` with no VPN, via `https://api.ui.com/v1/connector/consoles/{consoleId}/proxy/network/integration/...` (and `/proxy/protect/integration/...`). Documented constraints: console firmware >= 5.0.3; **100 requests/minute per console**; 25-second per-request timeout; 10 MB response body cap. Non-organization keys only reach the key owner's consoles; organization keys reach any console in the org.
   - Doc inconsistency: the connector's own description shows example paths without `/proxy`, while the `servers[]` entries in the Network and Protect specs, the path-parameter example, and `ai-gettingstarted.md` all include it. Use the `/proxy/...` form.

Network and Protect must work through **both** mode 2 and mode 3 behind one tool surface — the user picks the transport by configuration, not by calling different tools.

### Rate limits

- Site Manager: 10,000 req/min on stable `/v1/`; 100 req/min on Early Access `/ea/`. Returns 429 with a `Retry-After` header.
- Cloud Connector: 100 req/min per console — the binding constraint for proxied Network/Protect traffic.
- Mobility: **CONFLICT** — the spec's `info.description` says 100 req/min per key; the Getting Started page says 10,000 req/min. Both are currently published. Open question.
- Network and Protect, local mode: **UNVERIFIED** — not published. Open question.

### Response shapes — deliberately inconsistent across the four

Pagination:
- Site Manager: opaque cursor. `pageSize` (max 500) + `nextToken`; response returns `nextToken` while more remain.
- Network: offset/limit. `offset` (default 0) + `limit` (default 25, max 200); envelope `{count, data[], limit, offset, totalCount}`.
- Mobility: offset/limit. Envelope `{data[], total, offset, limit, httpStatusCode, traceId}`, default limit 200. Increment `offset` until `offset >= total`.
- Protect: **no pagination at all** — list endpoints take no query parameters and return full arrays.

Errors:
- Site Manager: `{code, httpStatusCode, message, traceId}`; codes `BAD_REQUEST`/`UNAUTHORIZED`/`FORBIDDEN`/`NOT_FOUND`/`RATE_LIMIT`/`SERVER_ERROR`/`BAD_GATEWAY`.
- Network: `{code, message, requestId, requestPath, statusCode, statusName, timestamp}`, with dotted codes like `api.authentication.missing-credentials`.
- Mobility: `{code, httpStatusCode, message, traceId}`; a present `body.code` means the error came from the gateway, not the upstream service. PUTs return 204 with an empty body.
- Protect: a `genericError` schema of `{error, name}`.

The server needs one normalized error and pagination contract across all four, or LLM clients will have to special-case per API.

### Network's filter DSL

Network alone supports a structured `filter` query parameter and it is expressive enough to be worth first-class modeling rather than passing through as an opaque string. Property expressions (`id.eq(123)`, `name.like('guest*')`, `createdAt.in(2025-01-01, 2025-01-05)`), compound `and(...)`/`or(...)`, negation `not(...)`. Types: STRING (single-quoted, `''` escapes a quote), INTEGER, DECIMAL, TIMESTAMP (ISO 8601), BOOLEAN, UUID, SET. Functions: `isNull`, `isNotNull`, `eq`, `ne`, `gt`, `ge`, `lt`, `le`, `like`, `in`, `notIn`, `isEmpty`, `contains`, `containsAny`, `containsAll`, `containsExactly`.

### Versioning and forward-compatibility

Ubiquiti publishes changes made **without advance notice**: new endpoints, new optional request parameters, new response properties, reordered response properties, and changed length/format of opaque strings (object IDs, error messages). Their stated best practice is to ignore unknown fields and tolerate unfamiliar properties, `null` values, and absent fields. Strict schema validation on responses will break in production. No formal deprecation or sunset policy is published — UNVERIFIED.

## Implementation path — the PRD feeds `mcp-server-dev:build-mcp-server`

Implementation will be done with the `mcp-server-dev:build-mcp-server` skill (Anthropic's official MCP server development skill). That skill opens with a discovery phase and refuses to scaffold until four decisions are settled: **deployment model, tool pattern, framework, and auth**. Its stated rule is "Do not start scaffolding until you have answers... If the user's opening message already answers them, acknowledge that and skip straight to the recommendation."

**The PRD's job is to answer those four questions with rationale, so the build skill skips discovery entirely.** Each must appear as an explicit, decided requirement — not a "to be determined" — with the trade-off reasoning recorded and any residual uncertainty pushed to Open Questions. Add a short section near the end titled "Handoff to build-mcp-server" that states the four decisions in one paragraph, in the form that skill expects as a design brief.

The build skill's own decision rules and constraints are given below. Use them as the framework; do not contradict them without saying why.

### Deployment model — the central architectural tension

The skill's default is emphatic: *"Remote streamable-HTTP... This is the recommended path for anything wrapping a cloud API. Choose this unless the server must touch the user's local machine."* MCPB (a bundled local server) is *"when the server must run on the user's machine — it reads local files, drives a desktop app, talks to localhost services, or needs OS-level access."* Local stdio is *"not recommended for distribution... Fine for personal tools and prototypes."*

UniFi splits down the middle of that rule, and the PRD must resolve it rather than inherit a default:

- Site Manager and Mobility are cloud APIs on `api.ui.com` — textbook remote HTTP.
- Network and Protect via Cloud Connector are also reachable from anywhere — remote HTTP works.
- **Network and Protect in local-direct mode are on the user's LAN at a private address. A remote HTTP server cannot reach `192.168.x.x`.** Local-direct support therefore requires a server running on the user's machine — local stdio or MCPB.
- **Auth compounds this.** UniFi uses a long-lived, user-supplied API key. The build skill states Claude does not support *"user-pasted bearer tokens (`static_bearer`)"*, and UniFi publishes no OAuth. A hosted multi-tenant remote server would need each user's UniFi key with no supported mechanism to collect it — which points away from remote hosting for a general-audience deployment.

Plausible resolutions to weigh explicitly: ship local stdio or MCPB and accept the distribution cost; ship remote HTTP covering only cloud + Connector paths and declare local-direct out of scope; or support both shapes from one codebase with the transport selected by configuration. Pick one, justify it, and state what the rejected options would have cost. If the answer is "local for now," say so plainly and note the skill's MCPB upgrade path rather than pretending remote was chosen.

### Tool pattern — the skill's thresholds

Verbatim from its guidance: 1–15 operations → one tool per action ("sweet spot"); 15–30 → "still workable, audit for near-duplicates"; **30+ → "switch to search + execute"**, i.e. a `search_actions` tool (natural-language intent → matching action IDs and schemas) plus an `execute_action` tool (run by ID). It also offers a hybrid: *"Promote the 3–5 most-used actions to dedicated tools, keep the long tail behind search/execute."*

The rationale is context economics, not a protocol limit: *"Every tool schema is tokens Claude spends every turn. Thirty tools with rich schemas can eat 3–5k tokens before the conversation even starts."* And explicitly: *"listing every operation as a tool floods the context window and degrades model performance."*

Four UniFi specs total roughly 200+ operations — far past the 30 threshold. Decide the pattern against this framework and, if hybrid, **name the specific 3–5 operations promoted to dedicated tools and justify each** (list sites, list devices, list clients, and list cameras are obvious candidates — argue it rather than assume it). Also decide whether tool exposure is filterable by configuration so a user who owns no Protect gear does not pay for its schemas.

### Framework

The skill recommends exactly two and has a default: **the official TypeScript SDK (`@modelcontextprotocol/sdk`) is the default choice** — "best spec coverage, first to get new features". **FastMCP 3.x** (jlowin's PyPI package, not the frozen FastMCP 1.0 inside the official `mcp` SDK) is the Python alternative — "user prefers Python, or wrapping a Python library". It adds: *"If the user already has a language/stack in mind, go with it — both produce identical wire protocol."*

The repo is greenfield with no stated preference, so recommend one of these two with reasoning tied to the actual workload (HTTP client, OpenAPI schema handling, and — if the answer is MCPB — runtime bundling). Do not propose a third language without arguing why both recommended options fail.

### Auth

Decide and specify: how the UniFi API key reaches the server, where it rests, and how multiple keys are handled if a user has both a cloud key and a local console key. Relevant constraints from the skill: for local/MCPB servers, tokens belong in the **OS keychain** (`keytar`/`keyring`) — *"Never plaintext on disk"*; MCPB manifests mark such fields `sensitive: true`; and *"Tool results flow into the chat transcript. Anything you return, the user (and any log export) can see. Redact before returning."* Elicitation **must not** be used to collect API keys.

### Non-negotiable constraints from the build skill — these become NFRs

Carry each of these into the NFR table as a testable requirement:

- **Read and write operations must be separate tools.** Directory review auto-rejects a single tool accepting both; documenting safe-vs-unsafe inside one tool's description does not satisfy it.
- **Every tool must carry `readOnlyHint`, `destructiveHint`, `idempotentHint` where applicable, and `title`** — these drive auto-approval and confirmation behavior in Claude.
- **Tool descriptions are the contract** and must describe what the tool does, what it returns, and what it does not do, and disambiguate near-siblings by naming them. Descriptions must not instruct Claude how to behave ("always call X first") — that is *"treated as prompt injection at review."*
- **Errors must be structured MCP tool errors**, not exceptions that crash the transport and not HTTP 500s with HTML bodies. The skill's shape is `{ isError: true, content: [...] }` with a recovery hint — *"The hint turns a dead end into a next step."*
- **Bound every list parameter in-schema** (`min`/`max`/`default`, hard caps) and **truncate-and-say-so**: e.g. `"Showing 10 of 847 results. Refine the query to narrow down."` Never return megabytes of unfiltered API response.
- **Payload ceilings are real numbers:** claude.ai and Claude Desktop truncate around **150,000 characters**; Claude Code around **25k tokens**. This binds directly on Protect's unpaginated arrays and on any large Network client list.
- Prefer `outputSchema` + `structuredContent`, but always include a text fallback — not all hosts read `structuredContent` yet.
- Tool names ≤ 64 characters, snake_case, and every parameter described.

## Product questions the PRD must answer

Beyond the four handoff decisions above, treat these as the substance of the document:

1. **Spec ingestion.** Are the four specs vendored into the repo as a build artifact and code generated from them, or fetched at runtime? What refreshes them when Ubiquiti ships new firmware versions, and how does a version bump get reviewed rather than silently absorbed? Note that the JSON→YAML conversion, if wanted, belongs here. Note also that Network and Protect declare no `securitySchemes`, so any codegen path needs a documented post-generation auth injection step.
2. **Read/write posture.** Site Manager is read-only today. Network, Protect, and Mobility have mutating endpoints (Mobility PUTs; Protect camera and device operations). What is the default posture for state-changing operations, and what must the user do to enable them? Reboots, adoptions, firmware updates, and client blocks are not undoable from a chat window. The skill's local-security guidance is relevant: *"Read-only by default... A tool that's read-only can't be weaponized into data loss no matter what Claude is tricked into calling it with"*, and for the most destructive operations, *"consider not shipping this at all."* Decide explicitly which UniFi operations, if any, fall in that last category.
3. **Response size.** Protect returns unpaginated arrays; the Connector caps bodies at 10 MB; the host truncates around 150k characters. What truncation, field-projection, or summarization strategy applies, and how is it verified?
4. **Configuration surface.** One user may have cloud-only Site Manager; another a local controller with a self-signed cert; another an org with many consoles reached via Connector. What does minimal viable configuration look like, and what is the discovery story for `consoleId` values?
5. **Prompt-injection exposure.** The skill states the threat model plainly: *"tool inputs are untrusted, even though they come from an AI the user trusts."* UniFi data contains user-controlled strings — SSIDs, client hostnames, device names, camera names — that flow from the network into tool output and then into the model's context. What, if anything, does the server do about that?

## Requirements for the artifact

Follow the standard PRD structure: Problem Statement; Goals & Success Metrics (Goal / Metric / Target / Baseline — baselines are honestly "none, greenfield" where that is true); User Personas; User Stories summary; Functional Requirements (`FR-01`…, with Priority and testable Acceptance Criteria); Non-Functional Requirements (`NFR-01`…, with Type and a measurable Target); Out of Scope; Dependencies & Risks; Timeline & Milestones; Open Questions with owners.

Specific constraints on the content:

- **Every functional requirement gets at least one acceptance criterion a QA engineer could write a test from.** No "should", "might", or "could" in acceptance criteria — use "must" or present-tense assertions.
- **Personas must be specific.** "Network operator" is too vague; distinguish, for example, a single-site home-lab owner from a multi-site MSP administrator, since they differ on Connector usage, organization keys, and console count.
- **Cover all four APIs explicitly.** A PRD that says "and the other APIs similarly" fails. Mobility in particular is easy to under-serve because it is the smallest spec — it still needs its own requirements covering app scoping, the 403-on-missing-scope path, and the 204-empty-body PUT behavior.
- **Out of Scope must be non-empty and specific.** Reasonable candidates to consider and decide on explicitly: the legacy/undocumented UniFi controller API, UniFi Access/Talk/Drive (no published developer APIs exist for these), Protect live video streaming and RTSP, and any UI beyond the MCP protocol itself.
- **Carry every CONFLICT and UNVERIFIED item above into Open Questions** with a named owner and a resolution path — do not resolve them by assertion.
- **Success metrics must be measurable.** "Good coverage" is not a metric; "N of M spec operations reachable, verified by a coverage check against the vendored specs" is.
- **The four build-skill decisions must be decided, not deferred** — deployment model, tool pattern, framework, auth — each with rationale, plus the "Handoff to build-mcp-server" paragraph near the end.
- **Timeline & Milestones must name the build skill explicitly** as the implementation step, with the PRD's acceptance as its entry gate. Verification milestones should use MCP Inspector (`npx @modelcontextprotocol/inspector`, and its `--cli` mode for CI smoke tests) rather than inventing a test approach — that is what the build skill prescribes, and it ships no test scaffolding of its own, so test strategy is a real gap the PRD should call out.
- State assumptions explicitly where you had to make one, and end with concrete next steps.

Do not write implementation code. This is a requirements document; `mcp-server-dev:build-mcp-server` does the implementation pass afterward, using this PRD as its design brief.
