# Fixture corpus

The recorded-response corpus the four contract suites run against (US-07), plus
the loader that reads it (`load.ts`) and the large-estate generator
(`large-estate/generate.mjs`).

## What these fixtures are, and what they are not

**They are hand-authored from the vendored OpenAPI response schemas.** They were
not recorded from a live UniFi console, because at this stage of the project no
live console exists to record from. Every body in this tree was written by
reading a schema — and, where the spec supplies one, an `example` — in
`specs/<service>/<version>/openapi.json`, and every file names the spec, the
operation and the JSON pointer it came from.

**This is a real fidelity limit and it should be stated plainly.** A contract
suite built on schema-derived fixtures proves that this server correctly handles
responses *conforming to the published schema*. It cannot prove anything about a
response that conforms to no published schema — an undocumented field, a
vendor-side shape change shipped ahead of the spec, a proxy that rewrites the
envelope. Those are invisible here. The mitigation is not more fixtures; it is
that `npm run specs:verify` pins the vendored spec bytes, so a spec that moves is
caught before the fixtures derived from it are silently stale, and each
fixture's `$provenance.pointer` names exactly what to go and re-derive when it
does. Replacing a fixture with a genuine recording, when a console becomes
available, is a strict improvement and the wrapper format is designed to make
that a one-file change.

## File format

Every fixture is a wrapper, because JSON has no comments and provenance that
lives only in a commit message does not survive to the reader who needs it:

```json
{
  "$provenance": {
    "spec": "specs/mobility/v1.0.0/openapi.json",
    "operation": "listDevices (GET /v1/mobility/workspaces/{workspaceID}/devices)",
    "pointer": "#/components/schemas/DeviceListResponse",
    "note": "What this particular case exercises."
  },
  "body": { "…": "the actual response body" }
}
```

`loadPageFixtures` / `loadErrorFixtures` return only `body`. All four
`$provenance` fields are **required**: a file missing any of them throws by
name at load time rather than joining the corpus silently. A fixture nobody can
trace back to a pointer is a fixture nobody can re-derive.

Fixtures are discovered by **directory listing**, so adding a case is one JSON
file and never an edit to a test. Files are sorted by name for determinism.

## Layout

```
test/fixtures/
├── README.md                     this file
├── load.ts                       loader + the shared cross-API assertions
├── large-estate/generate.mjs     deterministic multi-megabyte generator
├── site-manager/{pages,errors}/
├── network/{pages,errors}/
├── protect/{pages,errors}/
└── mobility/{pages,errors}/
```

## Provenance by set

| Set | Spec | Operation | Pointer |
|---|---|---|---|
| `site-manager/pages/sites-page{1,2}` | `specs/site-manager/v1.0.0/openapi.json` | `listSites` (`GET /v1/sites`) | `#/paths/~1v1~1sites/get/responses/200/…/schema` |
| `site-manager/pages/hosts-page1` | same | `listHosts` (`GET /v1/hosts`) | `#/paths/~1v1~1hosts/get/responses/200/…/schema` |
| `site-manager/errors/*` | same | mostly `listSites` / `getHostById` | inline per-path error object (this spec has **no** `components.schemas`) |
| `network/pages/clients-page{1,2}` | `specs/network/v10.4.57/openapi.json` | `getConnectedClientOverviewPage` (`GET /v1/sites/{siteId}/clients`) | `#/components/schemas/Client overview page` |
| `network/pages/devices-page1` | same | `getAdoptedDeviceOverviewPage` | `#/components/schemas/Adopted device overview page` |
| `network/errors/*` | same | **none — orphan schema** | `#/components/schemas/Error Message` |
| `protect/pages/cameras-*` | `specs/protect/v7.1.87/openapi.json` | `GET /v1/cameras` | `#/paths/~1v1~1cameras/get/responses/200/…/schema`, items `#/components/schemas/camera` |
| `protect/errors/*` | same | `default` response of `GET /v1/cameras` | `#/components/schemas/genericError` |
| `mobility/pages/devices-page{1,2,3}` | `specs/mobility/v1.0.0/openapi.json` | `listDevices` | `#/components/schemas/DeviceListResponse` |
| `mobility/errors/*` | same | `listDevices` / `listWorkspaces` | `#/components/schemas/ErrorResponse` |

The four envelopes have nothing in common, which is the whole reason the
normalizing layer exists:

- **site-manager** — `{code, data[], httpStatusCode, traceId, nextToken?}`.
  Cursor-paginated; no offset, no limit, no `totalCount`.
- **network** — `{count, data[], limit, offset, totalCount}`, all five required.
- **mobility** — `allOf` of `PaginationMeta` and `data[]`:
  `{data[], total, offset, limit, httpStatusCode, traceId}`. Only
  `httpStatusCode` and `traceId` are required, so `total` may legitimately be
  absent.
- **protect** — a **bare top-level array**. No envelope, no paging of any kind.

## Page chains

Each service's page fixtures form a chain that a test can walk by feeding
`nextCursor` back into `normalizePage`, and each chain terminates:

- **site-manager**: `sites-page1` carries a non-empty `nextToken`;
  `sites-page2` has none, so `nextCursor` and `truncation` are both null.
- **network**: `totalCount 5`, `limit 3` — `offset 0` (3 items) then
  `offset 3` (2 items) reaches 5 and stops.
- **mobility**: `total 7` split 3 / 3 / 1, terminating exactly at
  `offset + items.length >= total` (6 + 1 = 7). Three pages, each visited once.
- **protect**: `cameras-page1` is a four-camera bare array;
  `cameras-page2-empty` is the empty-array case a console with no adopted
  cameras returns.

## Error fixtures

Roughly eight to twelve bodies per service, each a few hundred bytes, one file
per case, table-driven — a newly observed error code is one new file.

Every service covers: an auth failure, a permission failure, a not-found, a
rate-limit (so a `Retry-After` test has a body to pair with), a server error,
and at least one degenerate body. Beyond that:

- **mobility** carries the FR-25 origin discriminator on both sides — a body
  **with** `code` (`origin: 'gateway'`) and one **without**
  (`origin: 'upstream'`) — and four distinct 403s, one for each branch of the
  FR-40 hint builder: an app-scope message, a workspace-role message, a
  subscription message, and the spec's own generic `"insufficient permissions"`,
  which matches none of the triggers and must produce the three-cause fallback.
- **protect** carries both the plain required `{error, name}` shape and one with
  the optional recursive `cause` nested two deep, since a nested object where
  the mapper expects a string is exactly what a naive parser trips on.

## Two discrepancies, recorded rather than papered over

**1. Site Manager error-code casing does not match the production lookup table.**

`SITE_MANAGER_CATEGORIES` in `src/http/errors.ts` is keyed on UPPERCASE names:
`BAD_REQUEST, UNAUTHORIZED, FORBIDDEN, NOT_FOUND, RATE_LIMIT, SERVER_ERROR,
BAD_GATEWAY`. The vendored spec's own examples are mostly lowercase, and are
internally inconsistent about it. Every distinct `code` in the spec:

`parameter_invalid` (400), `unauthorized` (401), `forbidden` (403),
`DeviceTimeout` (408), `NOT_FOUND` (404, on `/v1/hosts/{id}`), `not_found`
(404, on `/v1/sd-wan-configs/{id}`), `rate_limit` (429), `server_error` (500),
`bad_gateway` (502).

Three conventions in one spec — snake_case, SCREAMING_SNAKE and PascalCase — and
**no literal `BAD_REQUEST` anywhere**, so that table key is unreachable from
authentic data. Of the nine observed codes only `NOT_FOUND` hits the table; the
other eight fall through to the status→category map. That fallthrough happens to
produce the right category in every observed case, which is why this is a
recorded discrepancy and not a bug report — but it is load-bearing by accident,
and a future code with no matching status would land wrong.

So the corpus deliberately carries **both populations**: the authentic lowercase
codes the spec actually shows, and uppercase codes (`BAD_REQUEST`,
`UNAUTHORIZED`) authored only to exercise the table. Files in the second group
say so in their `$provenance.note`. In both cases **`upstreamCode` must survive
verbatim** — it is the only field a user can quote to Ubiquiti support, and
normalizing its casing would destroy exactly that.

**2. Network's `Error Message` schema is an orphan.**

`#/components/schemas/Error Message` is defined in the vendored Network spec and
`$ref`'d by **no operation**. In fact no Network operation declares any 4xx or
5xx response at all — every one of them documents only 200 or 201. The schema
also declares no `required` list, and its own property examples are mutually
inconsistent (`statusCode: 400` next to `statusName: "UNAUTHORIZED"`). Its only
example `code` is `api.authentication.missing-credentials`.

Everything in `network/errors/` is therefore hand-derived from an unreferenced
schema, which makes it the least authoritative set in this corpus. Field
presence in those fixtures is a judgement call, not a spec requirement. Treated
as a floor rather than a ceiling: the mapper must handle these, and must also
survive a Network error body that looks nothing like them.

A third, smaller note: `DEFAULT_PROJECTIONS.camera` projects `type`,
`isConnected` and `isRecording`, none of which appear in the vendored
`#/components/schemas/camera` (every one of whose sixteen properties is
required). Those three are runtime fields of the real Protect response, not the
integration schema. The committed cameras carry them anyway — a projection test
whose source objects lack the projected fields passes vacuously.

## Size policy

**Budget: under 80 KB committed under `test/fixtures/`, all of it small-file and
reviewable by eye.** Four small JSON directories and one generator script. The
point is that a reviewer can actually read the corpus; a corpus nobody reads
stops being evidence and becomes decoration.

Nothing multi-megabyte is ever committed. Two things are generated instead:

- **The 500-element Protect array.** `normalizePage`'s pagination-emulation path
  needs an array larger than Protect's 500-item page maximum. Committing 500
  near-identical cameras would exceed the entire corpus budget several times
  over, in content no reviewer would read past the third element. So the *shape*
  is committed once — element 0 of `protect/pages/cameras-page1.json`, carrying
  all sixteen required camera properties — and `syntheticProtectCameras(n)`
  expands it, varying `id`, `name` and `mac` so each element is distinct.

- **The large estate.** `large-estate/generate.mjs` builds, in memory at module
  load, a Protect camera array whose `JSON.stringify` length exceeds 10 MB
  (FR-51's stated shape) and a Network client list of more than 5 000 entries.
  Determinism is required by NFR-22, so there is no `Math.random`: the PRNG is a
  counter hashed with SHA-256 from a fixed seed, which makes element *N*
  identical on every machine, platform and process. Generation takes well under
  a second and is memoized via `largeEstate()`, comfortably inside the runner's
  60 000 ms per-test timeout.

  The generated items carry the real field names from the schemas above,
  including every field in `DEFAULT_PROJECTIONS`, **plus** enough extra bulk that
  projecting down to the default set is what brings a page under the payload
  ceiling. That is deliberate: the downstream test asserts the same page is over
  the ceiling unprojected and under it projected, which only proves the control
  is load-bearing if the discarded fields are what carried the weight.

- **The drift-fuzz corpus is not here at all.** It is generated at run time from
  a seed; nothing is committed for it.

## Maintenance

When a vendored spec is bumped:

1. `npm run specs:verify` fails first — it pins the spec bytes, so a moved spec
   is caught before anything derived from it goes quietly stale.
2. Each fixture's `$provenance` names the spec file, the operation and the
   pointer to re-read. Re-derive the ones whose pointer changed shape; leave the
   rest.
3. If an envelope changed, `src/http/pagination.ts` or `src/http/errors.ts`
   changes with it, and `assertPageEnvelope` / `assertErrorEnvelope` in
   `load.ts` are the single place the promised key sets are declared.

Adding a case never requires touching a test: drop a JSON file with complete
`$provenance` into the right directory and the loader picks it up.
