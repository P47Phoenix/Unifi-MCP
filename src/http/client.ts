/**
 * The single outbound HTTP path for all four APIs (FR-09, FR-12, FR-13, FR-26).
 *
 * Implemented on `node:https` rather than global `fetch`, for two reasons that
 * the requirements force rather than merely suggest:
 *
 *  - FR-09 needs per-host TLS control (a CA bundle, or a verification opt-in
 *    scoped to configured local consoles). Node 20's global `fetch` is undici
 *    based and accepts a custom TLS setup only through a `dispatcher`, and
 *    `undici` is NOT an installed dependency here — only `undici-types`, which
 *    is types-only. `node:https` gives the same control with no new dependency.
 *  - NFR-16 requires that a response above 10 MB is rejected rather than
 *    buffered whole. Counting bytes as they arrive and destroying the socket
 *    mid-stream is natural on an `IncomingMessage` and awkward on a `Response`.
 */
import { readFileSync } from 'node:fs';
import { Agent, request as httpsRequest } from 'node:https';
import type { IncomingMessage } from 'node:http';

import type { ServerConfig } from '../config.js';
import type { CredentialStore } from '../credentials.js';
import type { Action, ServiceId } from '../types.js';
import { UnifiError } from '../types.js';
import { localError, normalizeError } from './errors.js';
import type { RateLimiter } from './ratelimit.js';
import { bucketKeyFor, createRateLimiter } from './ratelimit.js';
import type { ResolvedTarget } from './transport.js';
import { CLOUD_HOST, buildUrl, resolveTarget } from './transport.js';

export interface UnifiResponse {
  status: number;
  body: unknown;
  headers: Headers;
}

export interface UnifiClientOptions {
  limiter?: RateLimiter;
  /** Diagnostics go to stderr, never stdout (NFR-19). */
  warn?: (message: string) => void;
  sleep?: (ms: number) => Promise<void>;
}

/**
 * Argument key selecting which configured local console to talk to, for
 * deployments with more than one. Only honoured when the action itself declares
 * no parameter of that name, so it can never shadow a real API parameter.
 */
export const CONSOLE_HOST_ARG = 'consoleHost';

/** Node TLS error codes that mean "the certificate did not verify" (FR-09). */
const CERT_ERROR_CODES = new Set([
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'CERT_HAS_EXPIRED',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'CERT_UNTRUSTED',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
]);

const RETRYABLE_STATUSES = new Set([408, 429, 502, 503, 504]);
const RETRYABLE_NETWORK_CODES = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'EAI_AGAIN',
  'EPIPE',
  'ENETUNREACH',
]);

/** Socket failures worth retrying, identified when the error is constructed. */
const TRANSIENT_ERRORS = new WeakSet<UnifiError>();

/**
 * `retryAfterSeconds` for an action abandoned before it computed a wait of its
 * own (FR-70 step 3, NFR-27).
 *
 * The figure is the rate limiter's queue ceiling — `DEFAULT_MAX_WAIT_MS` in
 * src/http/ratelimit.ts, 30 000 ms — so the hint a caller sees at shutdown
 * matches the longest wait the limiter would have imposed anyway. That constant
 * is module-private there and is deliberately not exported to satisfy this
 * file: widening `ratelimit.ts`'s surface for a hint value would be a worse
 * trade than restating the derived figure with its source named here.
 */
const SHUTDOWN_RETRY_AFTER_SECONDS = 30;

interface RawResponse {
  status: number;
  headers: Headers;
  text: string;
}

export class UnifiClient {
  private readonly limiter: RateLimiter;
  private readonly warn: (message: string) => void;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly agents = new Map<string, Agent>();
  private caBundle: Buffer | null = null;
  /** Handles of in-flight default backoff sleeps, so `close()` can release them. */
  private readonly pendingTimers = new Set<NodeJS.Timeout>();
  /** The controller behind each in-flight attempt; the only handle on one. */
  private readonly inFlight = new Set<AbortController>();
  /** Signals abandonment of a backoff or a credential resolution, never of an attempt. */
  private readonly drainAbort = new AbortController();
  private draining = false;
  private closed = false;

  constructor(
    private readonly config: ServerConfig,
    private readonly credentials: CredentialStore,
    options: UnifiClientOptions = {},
  ) {
    this.limiter = options.limiter ?? createRateLimiter(config);
    this.warn = options.warn ?? ((m) => process.stderr.write(`${m}\n`));
    this.sleep = options.sleep ?? ((ms) => this.trackedSleep(ms));

    if (config.caBundlePath) {
      try {
        this.caBundle = readFileSync(config.caBundlePath);
      } catch (e) {
        throw new UnifiError(
          localError(
            'network',
            'config',
            `UNIFI_LOCAL_CA_BUNDLE points at ${config.caBundlePath}, which could not be read ` +
              `(${(e as Error).message}).`,
            'Correct the path to a readable PEM bundle, or unset UNIFI_LOCAL_CA_BUNDLE.',
          ),
        );
      }
    }

    // FR-09: when the opt-in is active the operator gets told, at startup, on
    // stderr, exactly which hosts it covers — so a setting made once for one
    // console is never quietly in force for a fleet.
    if (config.localTlsInsecure) {
      const hosts = config.localConsoles.map((c) => c.host);
      this.warn(
        `unifi-mcp: WARNING — UNIFI_LOCAL_TLS_INSECURE is set. TLS certificate verification is ` +
          `DISABLED for ${hosts.length ? hosts.join(', ') : '(no local hosts configured)'}. ` +
          `Verification remains enforced for ${CLOUD_HOST} and cannot be disabled.`,
      );
    }
  }

  /** Test and observation seam; a drained client is never reopened. */
  get isDraining(): boolean {
    return this.draining;
  }

  /**
   * Stop admitting, abandon every wait, leave in-flight attempts alone (FR-70
   * step 3, NFR-27).
   *
   * Idempotent, synchronous and never throwing: a graceful drain must not be
   * able to block on the thing it is draining. In-flight HTTP attempts are
   * deliberately untouched — FR-70 step 4 requires the tool handlers already
   * running to finish under the existing per-attempt deadline, and aborting
   * here would truncate the very requests the drain promises to complete.
   */
  beginDrain(): void {
    if (this.draining) return;
    this.draining = true;

    // The only propagation path that can exist: `limiter` is private with no
    // accessor, so nothing outside this class can reach it. `RateLimiter.close`
    // is itself idempotent, synchronous and non-throwing (US-08), which is what
    // lets this method promise the same.
    this.limiter.close();

    // Last, so anything this wakes observes a fully drained client. The reason
    // is a fallback for anything reading `signal.reason`; each abandoned wait
    // builds its own service-specific error at rejection time.
    this.drainAbort.abort(
      this.shutdownError('site-manager', SHUTDOWN_RETRY_AFTER_SECONDS),
    );
  }

  /**
   * Drain, then release everything that holds the event loop open (FR-70 steps
   * 3, 4 and 7).
   *
   * Idempotent and never rejecting. Until this exists there is no call to
   * `agent.destroy()` anywhere in `src/`, and a pooled keep-alive socket is a
   * `ref`'d handle — so "the process exits 0 by natural event-loop drain" is
   * unreachable no matter how cleanly the inbound side shuts down.
   */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.beginDrain();

    // Before the agents, not after: destroying an agent first would surface as
    // ECONNRESET, which is in RETRYABLE_NETWORK_CODES and would earn the
    // request another attempt on the way out. Aborting produces the AbortError
    // that `transportError` maps to the shutdown error, which is terminal.
    for (const controller of this.inFlight) controller.abort();
    this.inFlight.clear();

    // Released, not merely un-awaited: a pending timer keeps the event loop
    // alive on its own, so abandoning the await without clearing the handle
    // still holds the process open to the hard stop on every clean shutdown.
    for (const handle of this.pendingTimers) clearTimeout(handle);
    this.pendingTimers.clear();

    for (const agent of this.agents.values()) {
      try {
        agent.destroy();
      } catch (e: unknown) {
        // Reported rather than swallowed, and swallowed rather than thrown:
        // one uncooperative agent must not abort the disposal of the rest, and
        // `close()` is called on the shutdown path where a rejection has no
        // handler that could do anything useful with it.
        this.warn(
          `unifi-mcp: an outbound agent failed to close during shutdown ` +
            `(${e instanceof Error ? e.message : String(e)}); its sockets may be released only ` +
            `when the process exits.`,
        );
      }
    }
    this.agents.clear();
  }

  async request(action: Action, args: Record<string, unknown> = {}): Promise<UnifiResponse> {
    // FR-44: the interceptor point. Writes are unreachable unless the operator
    // named the service in UNIFI_ENABLE_WRITES — no argument reaches this
    // check, so no tool call can talk its way past it.
    //
    // FR-71 AC 1a: over the HTTP serving transport this same set was already
    // narrowed ONCE, at configuration load, by UNIFI_HTTP_ALLOW_WRITES. Only
    // the MESSAGE branches on the surface — one condition, one decision, one
    // throw, so this stays the single outbound enforcement point and FR-71's
    // inventory still holds at two. The branch exists because an operator on
    // HTTP has typically already set UNIFI_ENABLE_WRITES, and the
    // transport-agnostic text would tell them to do the thing they have done.
    //
    // D-15: the HTTP message names THIS SERVICE and never claims the effective
    // set is empty. This branch is only reachable when the set is NON-empty —
    // `unifi_execute_write_action` is not advertised, and so not callable, when
    // it is empty (`src/tools/definitions.ts`, `writesEnabled.size === 0`) — so
    // the old "the intersection … is empty" sentence was false on every single
    // firing and told the operator to look at a set that was not the problem.
    if (action.actionClass === 'write' && !this.config.writesEnabled.has(action.service)) {
      const narrowedByHttpGate = this.config.activeSurface === 'http';
      throw new UnifiError(
        localError(
          action.service,
          'config',
          narrowedByHttpGate
            ? `Write actions for ${action.service} are disabled on the HTTP serving transport. ` +
              `Writes over HTTP require both UNIFI_ENABLE_WRITES and UNIFI_HTTP_ALLOW_WRITES, ` +
              `and ${action.service} is not in the effective set — the intersection of the two.`
            : `Action \`${action.id}\` is a ${action.method} (state-changing) operation and ` +
              `writes are not enabled for ${action.service}.`,
          narrowedByHttpGate
            ? `Set UNIFI_HTTP_ALLOW_WRITES to include this service on the server, then restart ` +
              `it.`
            : `Writes are off by default. To enable them, set ` +
              `UNIFI_ENABLE_WRITES=${action.service} (or a comma-separated list) in the server ` +
              `environment and restart. This cannot be enabled from a tool call.`,
        ),
      );
    }

    // FR-70 step 3: nothing new is admitted once the drain begins.
    //
    // Deliberately AFTER the write gate above and before target resolution or
    // URL construction. Placing it first would make a write-gated action during
    // drain return `rate_limit` instead of its FR-44 `config` refusal — moving
    // an enforcement point, which is exactly what this file's budget forbids.
    // The gate keeps its precedence; the drain only decides what happens to
    // work the gate already let through.
    if (this.draining) throw this.shutdownError(action.service, SHUTDOWN_RETRY_AFTER_SECONDS);

    const host = this.hostOverride(action, args);
    const target = resolveTarget(this.config, action.service, host);
    const { pathParams, query, headerParams, body } = splitArgs(action, args);
    const url = buildUrl(this.config, action, pathParams, query, host);

    // The call, its arguments and its result are unchanged; the wrapper adds
    // only the drain-abandonment path (FR-70 step 3). An action parked here
    // holds no rate-limit token and has issued no request, so it is failed for
    // exactly the reason a queued limiter waiter is failed.
    const apiKey = await this.abandonOnDrain(
      this.credentials.resolveFor(action.service, target.mode, target.host),
      action.service,
    );
    const bucketKey = bucketKeyFor(action, target);

    // FR-26: retries are for idempotent reads only. A write that fails is
    // surfaced, never replayed — a 429 on a PUT may still have been applied.
    const retryable = action.actionClass === 'read';
    const maxAttempts = retryable ? Math.max(1, this.config.retry.maxAttempts) : 1;

    let lastError: UnifiError | null = null;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      await this.limiter.acquire(bucketKey);

      let raw: RawResponse;
      try {
        raw = await this.send(action, target, url, apiKey, headerParams, body);
      } catch (e) {
        const err = e as UnifiError;
        const transient = retryable && err instanceof UnifiError && TRANSIENT_ERRORS.has(err);
        if (!transient || attempt === maxAttempts) throw err;
        lastError = err;
        await this.waitOrAbandon(this.backoffMs(attempt, null), action.service, lastError);
        continue;
      }

      if (raw.status < 400) {
        return { status: raw.status, body: parseBody(raw), headers: raw.headers };
      }

      const normalized = normalizeError(action.service, raw.status, parseBody(raw), raw.headers);
      const error = new UnifiError(
        target.mode === 'connector' ? withConnectorContext(normalized, target) : normalized,
      );

      if (!retryable || !RETRYABLE_STATUSES.has(raw.status) || attempt === maxAttempts) {
        throw error;
      }

      // FR-26: honour Retry-After, but only up to a bound — an hour-long
      // Retry-After is information for the caller, not a reason to block.
      const retryAfter = normalized.retryAfterSeconds;
      if (retryAfter !== null && retryAfter > this.config.retry.maxRetryAfterSeconds) throw error;

      lastError = error;
      await this.waitOrAbandon(this.backoffMs(attempt, retryAfter), action.service, lastError);
    }

    /* c8 ignore next */
    throw lastError ?? new UnifiError(localError(action.service, 'network', 'Request failed.'));
  }

  /** `Retry-After` wins when present; otherwise exponential backoff with jitter. */
  private backoffMs(attempt: number, retryAfterSeconds: number | null): number {
    if (retryAfterSeconds !== null) return retryAfterSeconds * 1000;
    const { baseDelayMs, maxDelayMs } = this.config.retry;
    const exponential = Math.min(maxDelayMs, baseDelayMs * 2 ** (attempt - 1));
    // Jitter keeps a fan-out across many consoles from re-colliding in lockstep.
    return Math.round(exponential * (0.5 + Math.random() / 2));
  }

  /**
   * Serve the retry backoff, unless the client is drained first.
   *
   * Abandonment is signalled by an `AbortController`, never by a long-lived
   * promise that is rejected at drain and raced with `Promise.race`. `race`
   * attaches a handler to that promise only while a backoff is actually in
   * progress, so on the overwhelmingly common shutdown — nothing in flight —
   * the rejection would land with no handler attached and Node's default
   * `--unhandled-rejections=throw` would terminate the process on the next
   * tick, before the remaining drain steps ran. An `AbortSignal` carries no
   * notion of an unhandled anything, and the rejection below is built inside a
   * continuation that always has a consumer. This is the same shape
   * `RateLimiter.waitOrAbandon` uses, and for the same reason.
   *
   * The listener is removed on either settlement path, so an idle process
   * accumulates nothing.
   *
   * There is no separate "stop retrying" check: the rejection propagates out of
   * `request()`, so no further attempt is a consequence of abandonment rather
   * than a second mechanism that could disagree with it.
   */
  private waitOrAbandon(waitMs: number, service: ServiceId, cause: unknown): Promise<void> {
    const signal = this.drainAbort.signal;
    // The seconds this backoff had already computed, carried through unchanged
    // rather than recomputed or nulled.
    const seconds = Math.ceil(waitMs / 1000);
    if (signal.aborted) return Promise.reject(this.shutdownError(service, seconds, cause));

    return new Promise<void>((resolve, reject) => {
      const onAbort = (): void => reject(this.shutdownError(service, seconds, cause));
      signal.addEventListener('abort', onAbort, { once: true });

      const settled = (): void => signal.removeEventListener('abort', onAbort);

      // When `close()` clears a pending default-sleep timer, that sleep's own
      // promise never resolves. Safe precisely because `onAbort` has already
      // rejected the promise returned here, so the awaiting caller is settled
      // either way — an awaiting caller is never left with a promise that never
      // settles.
      this.sleep(waitMs).then(
        () => {
          settled();
          resolve();
        },
        (error: unknown) => {
          settled();
          reject(error);
        },
      );
    });
  }

  /**
   * Fail an awaited preparation step when the drain begins.
   *
   * Same `AbortController` shape and same reasoning as `waitOrAbandon`; only
   * the thing being waited on differs.
   *
   * Abandoning the promise does NOT abandon the work behind it, and pretending
   * otherwise would be the more comfortable lie: on any shape carrying
   * `keytar`, an in-flight `getPassword` is a libuv threadpool request holding
   * a `ref`'d handle, so the *action* returns at once while the *process* still
   * waits for the keychain. The architecture records this as a known residual
   * (§2.4) whose only real fix — resolving credentials eagerly at startup — is
   * a behavioural change to startup that no requirement asks for. It is not
   * fixed here.
   */
  private abandonOnDrain<T>(work: Promise<T>, service: ServiceId): Promise<T> {
    const signal = this.drainAbort.signal;
    if (signal.aborted) {
      // No continuation is attached below on this path, so the work's own
      // settlement must be consumed here or an upstream credential failure
      // would surface later as an unhandled rejection.
      void work.catch(() => undefined);
      return Promise.reject(this.shutdownError(service, SHUTDOWN_RETRY_AFTER_SECONDS));
    }

    return new Promise<T>((resolve, reject) => {
      const onAbort = (): void =>
        reject(this.shutdownError(service, SHUTDOWN_RETRY_AFTER_SECONDS));
      signal.addEventListener('abort', onAbort, { once: true });

      const settled = (): void => signal.removeEventListener('abort', onAbort);

      // Attached unconditionally, so the abandoned work always has a consumer
      // for its eventual rejection even though nothing reads its value.
      work.then(
        (value) => {
          settled();
          resolve(value);
        },
        (error: unknown) => {
          settled();
          reject(error);
        },
      );
    });
  }

  /**
   * The default backoff sleep, with its handle captured so `close()` can
   * release it.
   *
   * Both halves are required and each alone is insufficient: the abort stops
   * the *action* waiting, the cleared handle stops the *process* being held
   * open. With only the abort, a 30-second `Retry-After` backoff keeps a
   * `ref`'d timer alive to the hard stop on an otherwise clean shutdown.
   *
   * The timer is deliberately NOT `unref()`'d: an unreferenced timer would let
   * the process exit while a legitimate in-flight tool call is still queued,
   * which is reachable on a short stdio session. `ratelimit.ts` records the same
   * departure for the same reason.
   */
  private trackedSleep(ms: number): Promise<void> {
    return new Promise<void>((resolve) => {
      const handle = setTimeout(() => {
        this.pendingTimers.delete(handle);
        resolve();
      }, ms);
      this.pendingTimers.add(handle);
    });
  }

  /**
   * The drain rejection: the existing `rate_limit` contract, naming shutdown.
   *
   * No new `ErrorCategory` member is introduced, which keeps NFR-24's closed
   * `reject_reason` vocabulary intact. The semantic cost is real — a caller
   * sees `rate_limit` for "the server is shutting down" — and FR-70 mandates
   * it. `retryAfterSeconds` is always a number, never null: every `rate_limit`
   * error this codebase constructs carries one, and the recovery hint reads it.
   */
  private shutdownError(
    service: ServiceId,
    retryAfterSeconds: number,
    cause?: unknown,
  ): UnifiError {
    const error = new UnifiError({
      category: 'rate_limit',
      service,
      httpStatus: null,
      upstreamCode: null,
      message:
        `The outbound client was shut down, so the ${service} request was released instead of ` +
        `being sent or retried. Nothing was rejected upstream.`,
      correlationId: null,
      origin: null,
      recoveryHint:
        `This server instance is shutting down and admits no further requests. Retry in ` +
        `${retryAfterSeconds}s against a newly started instance.`,
      retryAfterSeconds,
    });
    // `UnifiError`'s constructor takes only `normalized`, and src/types.ts is
    // outside this change's budget, so the failure that provoked the abandoned
    // wait is attached through the standard `Error.cause` property instead.
    // Discarding it is a diagnostic regression: it is the only surviving record
    // of why the request was retrying at all.
    if (cause !== undefined && cause !== null) error.cause = cause;
    return error;
  }

  private hostOverride(action: Action, args: Record<string, unknown>): string | undefined {
    if (action.parameters.some((p) => p.name === CONSOLE_HOST_ARG)) return undefined;
    const value = args[CONSOLE_HOST_ARG];
    return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
  }

  /**
   * TLS options for a host.
   *
   * FR-09 / NFR-14: the relaxation is scoped in code, not by convention. It
   * applies only to a host that appears in `localConsoles`, and `api.ui.com` is
   * short-circuited before the flag is even consulted.
   */
  private agentFor(host: string): Agent {
    const isCloud = host === CLOUD_HOST;
    const isConfiguredLocal = this.config.localConsoles.some((c) => c.host === host);
    const insecure = !isCloud && isConfiguredLocal && this.config.localTlsInsecure;
    const useBundle = !isCloud && this.caBundle !== null;

    const key = `${isCloud ? 'cloud' : host}|${insecure ? 'insecure' : 'verify'}|${useBundle ? 'ca' : 'system'}`;
    let agent = this.agents.get(key);
    if (!agent) {
      agent = new Agent({
        keepAlive: true,
        rejectUnauthorized: !insecure,
        ...(useBundle && this.caBundle ? { ca: this.caBundle } : {}),
      });
      this.agents.set(key, agent);
    }
    return agent;
  }

  private async send(
    action: Action,
    target: ResolvedTarget,
    url: string,
    apiKey: string,
    headerParams: Record<string, string>,
    body: unknown,
  ): Promise<RawResponse> {
    const payload =
      body === undefined || body === null
        ? null
        : Buffer.from(JSON.stringify(body), 'utf8');

    const headers: Record<string, string> = {
      // FR-13: unconditional, on every request to every service. Network and
      // Protect declare no security scheme in their specs; a client generated
      // straight from those specs would send nothing at all.
      'X-API-Key': apiKey,
      Accept: 'application/json',
      ...headerParams,
    };
    if (payload) {
      headers['Content-Type'] = action.requestBody?.contentType ?? 'application/json';
      headers['Content-Length'] = String(payload.byteLength);
    }

    // NFR-16: connector requests are abandoned at 25 seconds. The same bound is
    // applied to every transport — an unbounded local request would hang the
    // tool call just as effectively.
    const controller = new AbortController();
    const timeoutMs = this.config.connectorTimeoutMs;
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    // FR-70 step 7: this controller is the only handle on an in-flight attempt,
    // so tracking it is what makes `close()` able to abort one. Purely
    // additive — the controller already exists and is already passed as
    // `signal`; request construction is untouched.
    this.inFlight.add(controller);

    try {
      return await this.transmit(action, target, url, headers, payload, controller, timeoutMs);
    } finally {
      clearTimeout(timer);
      this.inFlight.delete(controller);
    }
  }

  private transmit(
    action: Action,
    target: ResolvedTarget,
    url: string,
    headers: Record<string, string>,
    payload: Buffer | null,
    controller: AbortController,
    timeoutMs: number,
  ): Promise<RawResponse> {
    const maxBytes = this.config.maxResponseBytes;

    return new Promise<RawResponse>((resolve, reject) => {
      let settled = false;
      const fail = (error: UnifiError) => {
        if (settled) return;
        settled = true;
        reject(error);
      };

      const req = httpsRequest(
        url,
        {
          method: action.method,
          headers,
          agent: this.agentFor(target.host),
          signal: controller.signal,
        },
        (res: IncomingMessage) => {
          const chunks: Buffer[] = [];
          let received = 0;

          res.on('data', (chunk: Buffer) => {
            received += chunk.byteLength;
            if (received > maxBytes) {
              // NFR-16: refuse without buffering the rest. Destroying the
              // response stops the transfer at the socket.
              res.destroy();
              req.destroy();
              fail(
                new UnifiError(
                  localError(
                    action.service,
                    'payload_too_large',
                    `The ${action.service} response exceeded the ${formatMb(maxBytes)} ceiling ` +
                      `and was abandoned mid-transfer; it was not buffered.`,
                    `Narrow the query: request a smaller page_size, add a filter, or select a ` +
                      `single resource by id instead of listing the collection.`,
                  ),
                ),
              );
            } else {
              chunks.push(chunk);
            }
          });

          res.on('end', () => {
            if (settled) return;
            settled = true;
            resolve({
              status: res.statusCode ?? 0,
              headers: toHeaders(res),
              text: Buffer.concat(chunks).toString('utf8'),
            });
          });

          res.on('error', (e: Error) => fail(this.transportError(action, target, e, timeoutMs)));
        },
      );

      req.on('error', (e: Error) => fail(this.transportError(action, target, e, timeoutMs)));

      if (payload) req.write(payload);
      req.end();
    });
  }

  /** Turn a socket-level failure into the right normalized category (FR-09, NFR-16). */
  private transportError(
    action: Action,
    target: ResolvedTarget,
    e: Error,
    timeoutMs: number,
  ): UnifiError {
    if (e instanceof UnifiError) return e;
    const code = (e as NodeJS.ErrnoException).code ?? '';

    if (e.name === 'AbortError' || code === 'ABORT_ERR') {
      // One added condition, exactly as the architecture's admit-list states
      // it. A drain-aborted attempt did not time out, and reporting a 25s
      // deadline that never elapsed is false to both the caller and the log.
      // A finer predicate — tracing the abort back to its own controller —
      // would be a deviation from the admit-list the diff-scope check is
      // written against, and buys nothing: while draining, no attempt is
      // waiting on anything else.
      if (this.draining) return this.shutdownError(action.service, SHUTDOWN_RETRY_AFTER_SECONDS, e);

      const where =
        target.mode === 'connector'
          ? `console ${target.consoleId} via the Cloud Connector`
          : `${target.host}`;
      return new UnifiError(
        localError(
          action.service,
          'timeout',
          `The request to ${where} was abandoned after ${Math.round(timeoutMs / 1000)}s.`,
          target.mode === 'connector'
            ? `Narrow the query and retry. If it persists, confirm console ${target.consoleId} is ` +
              `online, reachable from the UniFi cloud, and running firmware 5.0.3 or later — the ` +
              `Cloud Connector requires it.`
            : `Narrow the query and retry. If it persists, confirm ${target.host} is reachable ` +
              `from this machine.`,
        ),
      );
    }

    if (CERT_ERROR_CODES.has(code)) {
      // FR-09: exactly two remedies, both named precisely. A user reading this
      // should not have to go looking for what the setting is called.
      return new UnifiError(
        localError(
          action.service,
          'tls',
          `TLS certificate verification failed for ${target.host} (${code}). UniFi consoles ship ` +
            `self-signed certificates, so this is expected on a local console that has not been ` +
            `given a trusted certificate.`,
          `Two remedies, pick one: (1) set UNIFI_LOCAL_CA_BUNDLE to a PEM file containing the ` +
            `console certificate or its issuing CA, so verification succeeds; or (2) set ` +
            `UNIFI_LOCAL_TLS_INSECURE=true to accept unverified certificates for configured local ` +
            `console hosts only. Setting both is rejected at startup, and neither affects ` +
            `${CLOUD_HOST}.`,
        ),
      );
    }

    const error = new UnifiError(
      localError(
        action.service,
        'network',
        `Could not reach ${target.host}${code ? ` (${code})` : ''}: ${e.message}`,
      ),
    );
    // A refused connection is worth another attempt; a DNS name that does not
    // exist is not. The distinction is the errno, which does not survive into
    // NormalizedError, so it is recorded alongside the instance instead.
    if (RETRYABLE_NETWORK_CODES.has(code)) TRANSIENT_ERRORS.add(error);
    return error;
  }
}

/** FR-12: connector failures are also a firmware question; say so once, here. */
function withConnectorContext(
  normalized: ReturnType<typeof normalizeError>,
  target: ResolvedTarget,
): ReturnType<typeof normalizeError> {
  if (normalized.httpStatus !== 502 && normalized.httpStatus !== 503 && normalized.httpStatus !== 404) {
    return normalized;
  }
  return {
    ...normalized,
    recoveryHint:
      `${normalized.recoveryHint} This request was proxied through console ${target.consoleId}; ` +
      `the Cloud Connector requires console firmware 5.0.3 or later, and a non-organization key ` +
      `reaches only consoles owned by the key's account.`,
  };
}

function formatMb(bytes: number): string {
  return `${(bytes / (1024 * 1024)).toFixed(0)} MB`;
}

function toHeaders(res: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(res.headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) for (const v of value) headers.append(name, v);
    else headers.set(name, value);
  }
  return headers;
}

function parseBody(raw: RawResponse): unknown {
  if (raw.text === '') return null;
  const contentType = raw.headers.get('content-type') ?? '';
  if (contentType.includes('json') || /^\s*[[{]/.test(raw.text)) {
    try {
      return JSON.parse(raw.text);
    } catch {
      // Falls through to the raw string; normalizeError refuses to forward an
      // HTML body onward (NFR-05).
    }
  }
  return raw.text;
}

interface SplitArgs {
  pathParams: Record<string, unknown>;
  query: Record<string, unknown>;
  headerParams: Record<string, string>;
  body: unknown;
}

/**
 * Route tool arguments to where the spec says they belong.
 *
 * Anything the action does not declare as a parameter becomes the request body
 * for a write, and is dropped for a read — a read has nowhere to put it, and
 * silently appending it as a query parameter would invent API surface.
 */
function splitArgs(action: Action, args: Record<string, unknown>): SplitArgs {
  const pathParams: Record<string, unknown> = {};
  const query: Record<string, unknown> = {};
  const headerParams: Record<string, string> = {};
  const declared = new Set<string>([CONSOLE_HOST_ARG]);

  for (const parameter of action.parameters) {
    declared.add(parameter.name);
    const value = args[parameter.name];
    if (value === undefined || value === null) continue;
    if (parameter.location === 'path') pathParams[parameter.name] = value;
    else if (parameter.location === 'query') query[parameter.name] = value;
    else headerParams[parameter.name] = String(value);
  }

  let body: unknown;
  if (action.requestBody) {
    if (args.body !== undefined) {
      body = args.body;
    } else {
      const rest: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(args)) {
        if (!declared.has(key) && key !== 'body') rest[key] = value;
      }
      if (Object.keys(rest).length > 0) body = rest;
    }
  }

  return { pathParams, query, headerParams, body };
}

/** Re-exported so callers need one import for the request path. */
export type { ServiceId };
