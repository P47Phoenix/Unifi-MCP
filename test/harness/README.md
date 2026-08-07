# `test/harness/` — the FR-75 verification instruments

Nothing in this directory is a test. `scripts/run-tests.mjs` discovers suites with a
non-recursive `readdirSync('test').filter(n => n.endsWith('.test.ts'))`, so these files are
imported by suites, or spawned, and never executed as one. `test/instruments.test.ts` is the
suite that proves each instrument can fail before any other suite trusts it to pass.

| Module | What it is | Consumed by |
|---|---|---|
| `interceptor.ts` | A loopback HTTPS origin on `127.0.0.1:0` that the **production** `UnifiClient` dials. Records method, request target, every header, the `X-API-Key` value and the body. | FR-44 / FR-75 / FR-78 outbound assertions; US-16 AC 1, US-17 AC 1, US-15 AC 1b |
| `counters.ts` | The six named invocation counters as one `RuntimeDeps` + `ServingObserver` pair, plus the JSON wire format the spawned child reports them in. | A3, A20, C1, C9, the five startup refusals |
| `serve-entry.ts` | The spawnable child. Reads a JSON descriptor from `argv[2]`, calls the production `main(deps, observer)`, writes the counters to stderr as one prefixed line. | A2, A3, and every criterion needing injection **and** a real signal **and** an exit code in one run |
| `spawn.ts` | The parent side: launch, read counters, await exit, probe a port. | the same |

## The interceptor's operating envelope — stated, not discovered

The interceptor carries **only local-direct Network and Protect traffic.**

`src/http/transport.ts` declares the vendor origin as two module-level constants with no
environment override and no parameter, and `resolveTarget` returns them unconditionally for
Site Manager, for Mobility, and for **every** `connector`-mode request. That file is
untouchable this round — it is not one of the three named bounded exceptions — so no
configuration can point those three classes of request at a socket this process controls.

**Observable:** the real socket, method, URL, header set, `X-API-Key`, retry loop and TLS agent
selection, for Network and Protect in `local` mode.

**Not observable:** Site Manager, Mobility, and any service in `connector` mode. Those are
recorded instead by `test/fixtures/recording-client.ts` at the `UnifiClient.request` seam, which
proves *which request would have been built* and never that a socket carried it.
`mergeLedgers` joins both into one ledger and tags every entry with its recorder, so the two
grades of evidence cannot be confused.

Closing the gap is a six-line default parameter (`cloudBaseUrl: string = CLOUD_BASE_URL` on
`resolveTarget` / `resolveBaseUrl` / `buildUrl`, with the TLS `isCloud` test derived from it).
No story creates it, the architecture explicitly declined to add it, and it is the test
strategy's number-one residual coverage gap. **Do not add it here.**

## The certificate

`test/fixtures/loopback-cert.pem` and `loopback-key.pem` are committed. Node's standard library
exposes `crypto.generateKeyPairSync` but **no X.509 generation at all**; `selfsigned`,
`node-forge` and `mkcert` are dev dependencies, which FR-75 forbids; and `openssl` at test time
is not portable to the `windows-latest` leg NFR-20 requires green. Each `.pem` carries its own
banner giving the subject, the validity, the regeneration command, and why the key is inert.

It cannot rot: the origin is reached only with `UNIFI_LOCAL_TLS_INSECURE=true`, under which
`agentFor` sets `rejectUnauthorized: false` and neither the expiry nor the SAN is checked.

## Two rules every consumer inherits

- **Never omit `keychain`.** `createInstruments` always passes it, defaulting to `null`;
  `serve-entry.ts` pins it to `null` and offers no descriptor field to change it. `npm ci`
  installs `keytar` on the macOS and Windows legs, so a store built without it queries the
  runner's — or a developer's — real login keychain.
- **`.listen(0)`, always.** `run-tests.mjs` runs one child per file, concurrently; a fixed port
  is a collision waiting for a slow runner. S-09 asserts this over all of `test/`.
