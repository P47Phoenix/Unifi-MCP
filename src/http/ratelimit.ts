/**
 * Client-side outbound rate limiting (FR-12, FR-26, NFR-15).
 *
 * The point is to not inflict 429s on ourselves. Buckets are keyed by the thing
 * the limit is actually attached to — a console for Connector traffic, a path
 * class for Site Manager — rather than by service, because Site Manager's two
 * limits differ by a factor of 100 within one service (FR-30).
 */
import type { ServerConfig } from '../config.js';
import type { Action, ServiceId } from '../types.js';
import { UnifiError } from '../types.js';
import { localError } from './errors.js';
import type { ResolvedTarget } from './transport.js';

export interface BucketLimit {
  /** Sustained rate. Also the burst capacity, so a cold bucket allows one minute's worth. */
  requestsPerMinute: number;
  /** Longest a caller will wait in the queue before the limiter gives up. */
  maxWaitMs?: number;
}

interface Bucket {
  limit: BucketLimit;
  tokens: number;
  lastRefillMs: number;
  /** Serialises acquisitions so the queue is FIFO rather than a thundering herd. */
  tail: Promise<void>;
}

export interface RateLimiterOptions {
  /** Applied to any bucket with no explicit limit. */
  defaultLimit?: BucketLimit;
  limits?: Record<string, BucketLimit>;
  /** Injectable for tests; the limiter is otherwise wall-clock dependent. */
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

const DEFAULT_MAX_WAIT_MS = 30_000;

export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly limits: Map<string, BucketLimit>;
  private readonly defaultLimit: BucketLimit;
  private readonly now: () => number;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(options: RateLimiterOptions = {}) {
    this.limits = new Map(Object.entries(options.limits ?? {}));
    this.defaultLimit = options.defaultLimit ?? { requestsPerMinute: 100 };
    this.now = options.now ?? (() => Date.now());
    this.sleep = options.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }

  /** Limits may be set after construction; buckets pick the change up in place. */
  setLimit(bucketKey: string, limit: BucketLimit): void {
    this.limits.set(bucketKey, limit);
    const existing = this.buckets.get(bucketKey);
    if (existing) {
      existing.limit = limit;
      existing.tokens = Math.min(existing.tokens, limit.requestsPerMinute);
    }
  }

  /**
   * Wait until this bucket has a token.
   *
   * FR-12: a burst beyond the limit is queued, or rejected with a structured
   * rate-limit error carrying a retry hint. It is never silently dropped and
   * never silently sent anyway.
   */
  async acquire(bucketKey: string): Promise<void> {
    const bucket = this.bucketFor(bucketKey);

    // Chaining onto `tail` makes the wait computation exact: each waiter sees
    // the bucket state its predecessor left behind, so N concurrent callers
    // spread across N slots instead of all computing the same short delay.
    const turn = bucket.tail.then(() => this.consume(bucketKey, bucket));
    bucket.tail = turn.then(
      () => undefined,
      () => undefined,
    );
    return turn;
  }

  private async consume(bucketKey: string, bucket: Bucket): Promise<void> {
    this.refill(bucket);
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return;
    }

    const perMs = bucket.limit.requestsPerMinute / 60_000;
    const waitMs = Math.ceil((1 - bucket.tokens) / perMs);
    const maxWaitMs = bucket.limit.maxWaitMs ?? DEFAULT_MAX_WAIT_MS;

    if (waitMs > maxWaitMs) {
      const seconds = Math.ceil(waitMs / 1000);
      throw new UnifiError({
        category: 'rate_limit',
        service: serviceFromBucketKey(bucketKey),
        httpStatus: null,
        upstreamCode: null,
        message:
          `Client-side rate limit for \`${bucketKey}\` is saturated: the next slot is ${seconds}s ` +
          `away, beyond the ${Math.ceil(maxWaitMs / 1000)}s queue ceiling. The request was not ` +
          `sent — refusing here is cheaper than an upstream 429.`,
        correlationId: null,
        origin: null,
        recoveryHint:
          `Retry in ${seconds}s, or reduce concurrency. The bucket allows ` +
          `${bucket.limit.requestsPerMinute} requests/minute; raise it with the matching ` +
          `UNIFI_RATE_LIMIT_* environment variable only if the upstream limit genuinely permits it.`,
        retryAfterSeconds: seconds,
      });
    }

    await this.sleep(waitMs);
    this.refill(bucket);
    bucket.tokens = Math.max(0, bucket.tokens - 1);
  }

  private refill(bucket: Bucket): void {
    const now = this.now();
    const elapsedMs = Math.max(0, now - bucket.lastRefillMs);
    bucket.lastRefillMs = now;
    const gained = elapsedMs * (bucket.limit.requestsPerMinute / 60_000);
    bucket.tokens = Math.min(bucket.limit.requestsPerMinute, bucket.tokens + gained);
  }

  private bucketFor(bucketKey: string): Bucket {
    let bucket = this.buckets.get(bucketKey);
    if (!bucket) {
      const limit = this.limits.get(bucketKey) ?? this.defaultLimit;
      bucket = {
        limit,
        tokens: limit.requestsPerMinute,
        lastRefillMs: this.now(),
        tail: Promise.resolve(),
      };
      this.buckets.set(bucketKey, bucket);
    }
    return bucket;
  }
}

/** Bucket keys are `service:qualifier`; the prefix is recoverable for errors. */
function serviceFromBucketKey(bucketKey: string): ServiceId {
  const prefix = bucketKey.split(':')[0];
  switch (prefix) {
    case 'site-manager':
    case 'network':
    case 'protect':
    case 'mobility':
      return prefix;
    default:
      return 'site-manager';
  }
}

/**
 * The bucket an action's request belongs in.
 *
 * Connector traffic is bucketed per console because that is where the published
 * 100 req/min applies (FR-12, NFR-15) — two consoles through one key get one
 * bucket each, not a shared one.
 */
export function bucketKeyFor(action: Action, target: ResolvedTarget): string {
  if (target.mode === 'connector') return `${action.service}:connector:${target.consoleId}`;
  if (target.mode === 'local') return `${action.service}:local:${target.host}`;
  if (action.service === 'site-manager') return action.earlyAccess ? 'site-manager:ea' : 'site-manager:v1';
  return `${action.service}:cloud`;
}

/**
 * Seed a limiter from configuration.
 *
 * The Site Manager and Connector figures are published. The Mobility and
 * local-console figures are NOT: OQ-01 records that Ubiquiti publishes both
 * 100/min and 10,000/min for Mobility in different places, and OQ-02 records
 * that local Network/Protect limits are unpublished entirely. Both therefore
 * default to `PROVISIONAL_RATE_LIMIT_PER_MINUTE` in src/config.ts — a
 * conservative placeholder, overridable per bucket, deliberately not either
 * published Mobility figure. Revisit when OQ-01/OQ-02 close.
 */
export function createRateLimiter(
  config: ServerConfig,
  options: Omit<RateLimiterOptions, 'limits' | 'defaultLimit'> = {},
): RateLimiter {
  const limits: Record<string, BucketLimit> = {
    'site-manager:v1': { requestsPerMinute: config.rateLimits.siteManagerPerMinute },
    'site-manager:ea': { requestsPerMinute: config.rateLimits.siteManagerEarlyAccessPerMinute },
    'mobility:cloud': { requestsPerMinute: config.rateLimits.mobilityPerMinute },
  };

  const limiter = new RateLimiter({
    ...options,
    limits,
    // Connector and local buckets are created on demand with a per-console or
    // per-host key, so their limits are applied through this default rather
    // than enumerated up front.
    defaultLimit: { requestsPerMinute: config.rateLimits.connectorPerMinute },
  });

  // Local buckets can differ from the connector default, and their keys are
  // knowable up front from the configured hosts.
  for (const service of ['network', 'protect'] as const) {
    for (const console_ of config.localConsoles) {
      limiter.setLimit(`${service}:local:${console_.host}`, {
        requestsPerMinute: config.rateLimits.localPerMinute,
      });
    }
  }

  return limiter;
}
