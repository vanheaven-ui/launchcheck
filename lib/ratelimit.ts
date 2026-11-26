import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import { z } from "zod";

/**
 * Rate limiting for scan creation:
 *  - per-IP scans per hour (RATE_LIMIT_IP_PER_HOUR; default 10 in production,
 *    100 otherwise)
 *  - per-target scans per day (RATE_LIMIT_DOMAIN_PER_DAY; default 10), where a
 *    target is the site hostname or "github.com/<owner>/<repo>" — never a bare
 *    "github.com", which would put every repo scan in one global bucket.
 *
 * Uses Upstash Redis sliding windows when configured. In non-production
 * environments a simple in-memory sliding window is used instead; in
 * production a missing Upstash configuration fails closed (503).
 *
 * Rejected requests never consume tokens: every bucket is peeked first
 * (Upstash `getRemaining`, which does not consume) and only consumed via
 * `limit()` when all peeks pass. A consume can still fail if another request
 * races in between — that rare case reports the rejection and is documented
 * in docs/DECISIONS.md.
 */

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

const limitValue = z.coerce.number().int().min(1).max(100);

export type RateLimitConfig = {
  ipLimit: number;
  ipWindowMs: number;
  domainLimit: number;
  domainWindowMs: number;
};

function envLimit(name: string, fallback: number): number {
  const parsed = limitValue.safeParse(process.env[name]);
  return parsed.success ? parsed.data : fallback;
}

/** Effective limits for this process, read from env on every call. */
export function rateLimitConfig(): RateLimitConfig {
  return {
    ipLimit: envLimit("RATE_LIMIT_IP_PER_HOUR", process.env.NODE_ENV === "production" ? 10 : 100),
    ipWindowMs: HOUR_MS,
    domainLimit: envLimit("RATE_LIMIT_DOMAIN_PER_DAY", 10),
    domainWindowMs: DAY_MS,
  };
}

export type RateLimitScope = "ip" | "domain";

export type RateLimitDecision =
  | { allowed: true }
  | { allowed: false; status: 503 }
  | {
      allowed: false;
      status: 429;
      scope: RateLimitScope;
      retryAfterSeconds: number;
    };

/** A single bucket check: `peek` does not consume, `consume` records a hit. */
type WindowStore = {
  peek(key: string): Promise<{ success: boolean; reset: number }>;
  consume(key: string): Promise<{ success: boolean; reset: number }>;
};

function upstashStore(
  limit: number,
  window: `${number} ${"ms" | "s" | "m" | "h" | "d"}`,
): WindowStore {
  const redis = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL as string,
    token: process.env.UPSTASH_REDIS_REST_TOKEN as string,
  });
  const ratelimit = new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(limit, window),
    prefix: "launchcheck",
  });
  return {
    peek: async (key) => {
      const result = await ratelimit.getRemaining(key);
      return { success: result.remaining > 0, reset: result.reset };
    },
    consume: async (key) => {
      const result = await ratelimit.limit(key);
      return { success: result.success, reset: result.reset };
    },
  };
}

/** In-memory sliding window: Map<key, timestamps[]> pruned on each check. */
export class InMemorySlidingWindow {
  private hits = new Map<string, number[]>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
  ) {}

  private evaluate(
    key: string,
    now: number,
  ): { entries: number[]; success: boolean; reset: number } {
    const cutoff = now - this.windowMs;
    const entries = (this.hits.get(key) ?? []).filter((ts) => ts > cutoff);
    if (entries.length >= this.limit) {
      const oldest = entries[0];
      return {
        entries,
        success: false,
        reset: oldest === undefined ? now + this.windowMs : oldest + this.windowMs,
      };
    }
    return { entries, success: true, reset: now + this.windowMs };
  }

  /** Would the next check pass? Does not record a hit. */
  async peek(key: string, now: number = Date.now()): Promise<{ success: boolean; reset: number }> {
    const { success, reset } = this.evaluate(key, now);
    return { success, reset };
  }

  async check(key: string, now: number = Date.now()): Promise<{ success: boolean; reset: number }> {
    const { entries, success, reset } = this.evaluate(key, now);
    // Only allowed requests are recorded; a rejected check must never extend
    // the block for a user who keeps retrying.
    if (success) {
      entries.push(now);
    }
    this.hits.set(key, entries);
    return { success, reset };
  }

  /** Test helper: drop all recorded hits. */
  reset(): void {
    this.hits.clear();
  }
}

const memoryWindows = new Map<string, { ip: WindowStore; domain: WindowStore }>();
const upstashWindows = new Map<string, { ip: WindowStore; domain: WindowStore }>();

function memoryStore(window: InMemorySlidingWindow): WindowStore {
  return {
    peek: (key) => window.peek(key),
    consume: (key) => window.check(key),
  };
}

function getStores(config: RateLimitConfig): { ip: WindowStore; domain: WindowStore } | null {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  const cacheKey = `${config.ipLimit}/${config.domainLimit}`;

  if (url && token) {
    let stores = upstashWindows.get(cacheKey);
    if (!stores) {
      stores = {
        ip: upstashStore(config.ipLimit, "1 h"),
        domain: upstashStore(config.domainLimit, "1 d"),
      };
      upstashWindows.set(cacheKey, stores);
    }
    return stores;
  }
  if (process.env.NODE_ENV !== "production") {
    let stores = memoryWindows.get(cacheKey);
    if (!stores) {
      stores = {
        ip: memoryStore(new InMemorySlidingWindow(config.ipLimit, config.ipWindowMs)),
        domain: memoryStore(new InMemorySlidingWindow(config.domainLimit, config.domainWindowMs)),
      };
      memoryWindows.set(cacheKey, stores);
    }
    return stores;
  }
  return null;
}

function retryAfterSeconds(reset: number): number {
  return Math.max(1, Math.ceil((reset - Date.now()) / 1000));
}

type BucketCheck = { scope: RateLimitScope; key: string; reset: number };

/**
 * Check the per-IP limit and every per-target limit for a scan attempt.
 * `targets` are already-normalized bucket keys (site hostname, or
 * "github.com/<owner>/<repo>"). All buckets are peeked first so a rejection
 * never consumes a token from another bucket; consumption happens only when
 * every peek passes.
 */
export async function checkScanRateLimits(input: {
  ip: string;
  targets: string[];
}): Promise<RateLimitDecision> {
  const stores = getStores(rateLimitConfig());
  if (!stores) {
    return { allowed: false, status: 503 };
  }

  const buckets: BucketCheck[] = [
    { scope: "ip", key: `ip:${input.ip}`, reset: 0 },
    ...input.targets.map((target) => ({
      scope: "domain" as const,
      key: `domain:${target}`,
      reset: 0,
    })),
  ];
  const storeFor = (scope: RateLimitScope) => (scope === "ip" ? stores.ip : stores.domain);

  // Peek every bucket; collect rejections without consuming anything.
  const rejected: { scope: RateLimitScope; retryAfterSeconds: number }[] = [];
  for (const bucket of buckets) {
    const result = await storeFor(bucket.scope).peek(bucket.key);
    if (!result.success) {
      rejected.push({
        scope: bucket.scope,
        retryAfterSeconds: retryAfterSeconds(result.reset),
      });
    }
  }
  if (rejected.length > 0) {
    // Report the longest wait when several buckets reject.
    const worst = rejected.reduce((a, b) => (b.retryAfterSeconds > a.retryAfterSeconds ? b : a));
    return {
      allowed: false,
      status: 429,
      scope: worst.scope,
      retryAfterSeconds: worst.retryAfterSeconds,
    };
  }

  // All peeks passed: consume. A failure here means a concurrent request raced
  // the peek; report it (other buckets may already hold a consumed token).
  for (const bucket of buckets) {
    const result = await storeFor(bucket.scope).consume(bucket.key);
    if (!result.success) {
      return {
        allowed: false,
        status: 429,
        scope: bucket.scope,
        retryAfterSeconds: retryAfterSeconds(result.reset),
      };
    }
  }

  return { allowed: true };
}

/** First value of x-forwarded-for, then x-real-ip, then a shared bucket key. */
export function getClientIp(headers: Headers): string {
  const forwarded = headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0]?.trim();
    if (first) {
      return first;
    }
  }
  const realIp = headers.get("x-real-ip")?.trim();
  if (realIp) {
    return realIp;
  }
  return "unknown";
}
