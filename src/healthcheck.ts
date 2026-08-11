/**
 * `--healthcheck`: the container probe (FR-68, NFR-25, §14 item 10).
 *
 * `src/index.ts` owns the argv branch — both mode flags are named there, in the
 * literal form Out of Scope #22's source scan permits, and this module reads no
 * argv at all. What it owns is the verdict.
 *
 * ## Why `--healthcheck` is not `--selftest`
 *
 * `--selftest` answers *"is this artifact intact"*: it parses four OpenAPI
 * specs, builds the whole action registry and resolves every promoted tool.
 * That is real startup work, and the Dockerfile ran it on every probe tick —
 * every 60 seconds, forever, in a second interpreter. NFR-25 forbids repeating
 * startup work per probe, and §14 item 10 names the `HEALTHCHECK` as the thing
 * to reconcile with FR-68/FR-69/NFR-25.
 *
 * The second reason is worse than the cost. Under `UNIFI_MCP_TRANSPORT=http` a
 * self-test cannot observe drain **at all**: it reads the image, not the
 * process, so it reports healthy right up to the instant the process exits. A
 * liveness probe that cannot see the process it is probing is not a liveness
 * probe. Under HTTP this module therefore asks the running process, over the
 * loopback interface, on the endpoint whose contract is *"200 while bound,
 * unchanged throughout drain"* — the one signal that keeps Docker from
 * SIGKILLing a container in the middle of a graceful shutdown.
 *
 * Under stdio there is nothing bound to ask, so `--healthcheck` delegates to
 * `selfTest()` and today's behaviour is preserved exactly.
 *
 * ## What this module must NOT do
 *
 * Under HTTP: build no action registry, construct no `CredentialStore`, read no
 * spec manifest and issue no outbound UniFi request. It reads two environment
 * variables and opens one loopback socket. Nothing here imports
 * `src/serve/**` — architecture §9.4 permits the literal `serve/` in an import
 * specifier only inside `src/serve/` itself and in `src/index.ts` — and nothing
 * here imports `src/config.ts`, because `loadConfig`/`validateConfig` ARE the
 * startup work NFR-25 is about, and because a probe that refused on an
 * unrelated misconfiguration would report the wrong problem (the same reasoning
 * that keeps `--selftest` credential-free).
 *
 * The price of not importing `config.ts` is that `probeTransport` and
 * `probePort` below are SECOND implementations of `resolveServingTransport`
 * (`config.ts:641`) and `readPort` (`config.ts:368`). They are deliberate and
 * differentially pinned: `test/healthcheck.test.ts` drives both against
 * `loadConfig` over a table of raw values and asserts they agree, so a change
 * to either side turns a test red rather than leaving the probe addressing a
 * port the server never bound. Recorded for US-30's duplicate-primitive
 * inventory alongside `log.ts`'s `sanitizeTrusted` and `renderBindAddress`.
 *
 * ## Exit codes
 *
 * `0` healthy, `1` unhealthy, and never anything else: Docker reserves `2` and
 * documents it as "do not use", so every failure — refused connection, timeout,
 * non-200, malformed response — collapses to `1`. Nothing here throws, so the
 * entrypoint's `await` cannot reject and a probe never dies with a stack trace
 * instead of a verdict.
 */
import {
  request as httpRequest,
  type ClientRequest,
  type IncomingMessage,
  type RequestOptions,
} from 'node:http';

import { selfTest } from './selftest.js';

/**
 * Always loopback, never `UNIFI_HTTP_BIND`.
 *
 * The probe runs INSIDE the container, in the same network namespace as the
 * listener, so it addresses the process rather than the deployment. A container
 * bound to `0.0.0.0` — which §5.15.1 says a container needs, or its orchestrator
 * probes cannot reach it — is still reachable on `127.0.0.1`, and a probe that
 * dialled `0.0.0.0` would be asking the network what it should be asking the
 * process.
 */
export const PROBE_HOST = '127.0.0.1';

/** FR-68's endpoint. Reserved by FR-73(d), so no configuration can move it. */
export const PROBE_PATH = '/healthz';

/** `config.ts:602`'s fallback for `UNIFI_HTTP_PORT`, and `Dockerfile`'s `EXPOSE`. */
export const DEFAULT_PROBE_PORT = 8787;

/**
 * Comfortably inside the `HEALTHCHECK --timeout=15s` the Dockerfile declares, so
 * a wedged listener produces *this* module's `1` rather than Docker's own
 * timeout kill — the two are indistinguishable to an operator reading
 * `docker inspect`, and only one of them is a verdict.
 */
export const PROBE_TIMEOUT_MS = 5_000;

const HEALTHY = 0;
const UNHEALTHY = 1;

/** `config.ts:354-355`. `0` means "OS-assigned" and is a port no probe can dial. */
const MIN_PORT = 0;
const MAX_PORT = 65_535;

/** The `node:http` seam. A default parameter, because Node 20 has no `mock.module`. */
export type RequestFn = (
  options: RequestOptions,
  callback: (response: IncomingMessage) => void,
) => ClientRequest;

export interface HealthcheckDeps {
  /** The configuration source. Defaults to `process.env`, never captured at import. */
  readonly env?: NodeJS.ProcessEnv;
  /** The outbound seam. Defaults to `node:http`'s `request`. */
  readonly request?: RequestFn;
  /** The stdio delegate. Defaults to the real `selfTest`. */
  readonly selfTest?: () => number;
  readonly timeoutMs?: number;
}

/** ASCII case folding only, mirroring `config.ts:450` — `toLowerCase()` is locale-aware. */
function asciiLowerCase(value: string): string {
  return value.replace(/[A-Z]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) + 32));
}

/**
 * The transport this probe should use, by the same rules `config.ts` resolves
 * `activeSurface` with: unset is `stdio`, blank-after-trimming is `stdio`, and
 * an unrecognised non-blank token is `stdio` too — fail-closed, because the
 * fallback binds no listener and a probe that guessed `http` there would report
 * a healthy stdio container unhealthy on every tick.
 */
export function probeTransport(env: NodeJS.ProcessEnv): 'stdio' | 'http' {
  const raw = env['UNIFI_MCP_TRANSPORT'];
  if (raw === undefined) return 'stdio';
  return asciiLowerCase(raw.trim()) === 'http' ? 'http' : 'stdio';
}

/** `readPort` (`config.ts:368`) without the diagnostics: an out-of-range value falls back. */
export function probePort(env: NodeJS.ProcessEnv): number {
  const raw = env['UNIFI_HTTP_PORT'];
  if (raw === undefined || raw.trim() === '') return DEFAULT_PROBE_PORT;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < MIN_PORT || n > MAX_PORT) return DEFAULT_PROBE_PORT;
  return n;
}

/**
 * The probe. Returns an exit code and never throws.
 *
 * Under stdio this is `selfTest()` verbatim — the one case where this story
 * deliberately changes nothing.
 */
export async function healthcheck(deps: HealthcheckDeps = {}): Promise<number> {
  const env = deps.env ?? process.env;
  if (probeTransport(env) !== 'http') return (deps.selfTest ?? selfTest)();
  return probeHealthz(probePort(env), deps);
}

/**
 * Exactly one `GET`, and no retry under any circumstance.
 *
 * `HEALTHCHECK --retries=3` already owns the retry policy, and a probe that
 * retried internally would multiply the daemon's budget by its own and turn a
 * 15-second timeout into a 45-second one. `agent: false` gives the request its
 * own socket rather than the keep-alive global agent's, so the connection dies
 * with the request and the process holds nothing open.
 */
function probeHealthz(port: number, deps: HealthcheckDeps): Promise<number> {
  const send = deps.request ?? httpRequest;
  const timeout = deps.timeoutMs ?? PROBE_TIMEOUT_MS;

  return new Promise<number>((resolve) => {
    // Every path below can fire more than once — a socket error after a
    // response, a timeout racing the status line. The verdict is whichever
    // arrives first, and the rest are dropped.
    let settled = false;
    const settle = (code: number): void => {
      if (settled) return;
      settled = true;
      resolve(code);
    };

    let probe: ClientRequest;
    try {
      probe = send(
        { host: PROBE_HOST, port, path: PROBE_PATH, method: 'GET', agent: false, timeout },
        (response) => {
          // Drain rather than read: FR-67 makes the body `ok\n`, and the status
          // line is the whole of the contract this probe depends on. Reading
          // the body would make the probe's cost a function of what an
          // attacker-influenced response chose to send.
          response.resume();
          settle(response.statusCode === 200 ? HEALTHY : UNHEALTHY);
        },
      );
    } catch {
      // A synchronous throw out of `request` — an unparseable port, say.
      settle(UNHEALTHY);
      return;
    }

    probe.on('timeout', () => probe.destroy());
    probe.on('error', () => settle(UNHEALTHY));
    probe.end();
  });
}
