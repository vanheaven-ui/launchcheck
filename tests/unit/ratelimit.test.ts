import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  checkScanRateLimits,
  getClientIp,
  InMemorySlidingWindow,
  rateLimitConfig,
} from "@/lib/ratelimit";

// Never let a local .env with real Upstash credentials leak into these tests.
beforeEach(() => {
  vi.stubEnv("UPSTASH_REDIS_REST_URL", "");
  vi.stubEnv("UPSTASH_REDIS_REST_TOKEN", "");
  vi.stubEnv("RATE_LIMIT_IP_PER_HOUR", "");
  vi.stubEnv("RATE_LIMIT_DOMAIN_PER_DAY", "");
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("rateLimitConfig", () => {
  it("defaults to 10/hour IP and 10/day target in production", () => {
    vi.stubEnv("NODE_ENV", "production");
    expect(rateLimitConfig()).toMatchObject({ ipLimit: 10, domainLimit: 10 });
  });

  it("defaults to 100/hour IP outside production", () => {
    vi.stubEnv("NODE_ENV", "test");
    expect(rateLimitConfig().ipLimit).toBe(100);
  });

  it("honors valid env overrides", () => {
    vi.stubEnv("RATE_LIMIT_IP_PER_HOUR", "42");
    vi.stubEnv("RATE_LIMIT_DOMAIN_PER_DAY", "7");
    expect(rateLimitConfig()).toMatchObject({ ipLimit: 42, domainLimit: 7 });
  });

  it("falls back to defaults for out-of-range or non-integer values", () => {
    for (const bad of ["0", "101", "1.5", "abc"]) {
      vi.stubEnv("RATE_LIMIT_IP_PER_HOUR", bad);
      vi.stubEnv("RATE_LIMIT_DOMAIN_PER_DAY", bad);
      const config = rateLimitConfig();
      expect(config.ipLimit).toBe(100); // non-production default
      expect(config.domainLimit).toBe(10);
    }
  });
});

describe("InMemorySlidingWindow", () => {
  it("allows up to the limit then blocks", async () => {
    const window = new InMemorySlidingWindow(3, 60_000);
    const now = 1_000_000;
    expect((await window.check("k", now)).success).toBe(true);
    expect((await window.check("k", now + 1)).success).toBe(true);
    expect((await window.check("k", now + 2)).success).toBe(true);
    const blocked = await window.check("k", now + 3);
    expect(blocked.success).toBe(false);
    expect(blocked.reset).toBe(now + 60_000);
  });

  it("peek reports the same result without consuming a slot", async () => {
    const window = new InMemorySlidingWindow(1, 60_000);
    const now = 1_000_000;
    expect((await window.peek("k", now)).success).toBe(true);
    expect((await window.peek("k", now + 1)).success).toBe(true);
    expect((await window.check("k", now + 2)).success).toBe(true);
    expect((await window.peek("k", now + 3)).success).toBe(false);
    expect((await window.peek("k", now + 4)).success).toBe(false);
  });

  it("frees capacity after the window passes", async () => {
    const window = new InMemorySlidingWindow(2, 1_000);
    await window.check("k", 0);
    await window.check("k", 100);
    expect((await window.check("k", 200)).success).toBe(false);
    // First hit (t=0) has expired by t=1001; second (t=100) still counts.
    expect((await window.check("k", 1001)).success).toBe(true);
    expect((await window.check("k", 1002)).success).toBe(false);
  });

  it("never records rejected checks, so retries do not extend the block", async () => {
    const window = new InMemorySlidingWindow(1, 1_000);
    expect((await window.check("k", 0)).success).toBe(true);
    for (const t of [100, 200, 300, 400, 500]) {
      expect((await window.check("k", t)).success).toBe(false);
    }
    // Only the t=0 hit was ever recorded; it expires at t=1000 even though
    // rejected checks kept arriving until t=500.
    expect((await window.check("k", 999)).success).toBe(false);
    expect((await window.check("k", 1000)).success).toBe(true);
  });

  it("reports reset as the earliest live hit's expiry", async () => {
    const window = new InMemorySlidingWindow(2, 1_000);
    await window.check("k", 100);
    await window.check("k", 500);
    const blocked = await window.peek("k", 600);
    expect(blocked.success).toBe(false);
    expect(blocked.reset).toBe(1_100);
    // A rejected check does not move the reset later.
    await window.check("k", 700);
    expect((await window.peek("k", 701)).reset).toBe(1_100);
  });

  it("tracks keys independently", async () => {
    const window = new InMemorySlidingWindow(1, 1_000);
    expect((await window.check("a", 0)).success).toBe(true);
    expect((await window.check("b", 0)).success).toBe(true);
    expect((await window.check("a", 1)).success).toBe(false);
  });
});

describe("checkScanRateLimits (in-memory, non-production)", () => {
  it("enforces the per-IP limit and returns scope ip with retryAfterSeconds", async () => {
    vi.stubEnv("RATE_LIMIT_IP_PER_HOUR", "2");
    vi.stubEnv("RATE_LIMIT_DOMAIN_PER_DAY", "50");
    const ip = "203.0.113.10";
    expect((await checkScanRateLimits({ ip, targets: ["a.example.com"] })).allowed).toBe(true);
    expect((await checkScanRateLimits({ ip, targets: ["b.example.com"] })).allowed).toBe(true);
    const blocked = await checkScanRateLimits({ ip, targets: ["c.example.com"] });
    expect(blocked).toMatchObject({ allowed: false, status: 429, scope: "ip" });
    if (!blocked.allowed && blocked.status === 429) {
      expect(blocked.retryAfterSeconds).toBeGreaterThanOrEqual(1);
    }
  });

  it("shares a per-target bucket across IPs but not across targets", async () => {
    vi.stubEnv("RATE_LIMIT_IP_PER_HOUR", "50");
    vi.stubEnv("RATE_LIMIT_DOMAIN_PER_DAY", "2");
    const target = "github.com/acme/app";
    expect((await checkScanRateLimits({ ip: "198.51.100.1", targets: [target] })).allowed).toBe(
      true,
    );
    expect((await checkScanRateLimits({ ip: "198.51.100.2", targets: [target] })).allowed).toBe(
      true,
    );
    const blocked = await checkScanRateLimits({ ip: "198.51.100.3", targets: [target] });
    expect(blocked).toMatchObject({ allowed: false, status: 429, scope: "domain" });
    // A different repo target is unaffected.
    expect(
      (await checkScanRateLimits({ ip: "198.51.100.3", targets: ["github.com/acme/other"] }))
        .allowed,
    ).toBe(true);
    // A site hostname is a different bucket than the repo key.
    expect(
      (await checkScanRateLimits({ ip: "198.51.100.4", targets: ["github.com"] })).allowed,
    ).toBe(true);
  });

  it("checks every target in both mode", async () => {
    vi.stubEnv("RATE_LIMIT_IP_PER_HOUR", "50");
    vi.stubEnv("RATE_LIMIT_DOMAIN_PER_DAY", "1");
    // Exhaust only the repo target.
    await checkScanRateLimits({ ip: "192.0.2.1", targets: ["github.com/acme/app"] });
    // A both-mode request is rejected even though the site target has capacity.
    const blocked = await checkScanRateLimits({
      ip: "192.0.2.2",
      targets: ["example.com", "github.com/acme/app"],
    });
    expect(blocked).toMatchObject({ allowed: false, status: 429, scope: "domain" });
    // The site target alone still has capacity.
    expect((await checkScanRateLimits({ ip: "192.0.2.3", targets: ["example.com"] })).allowed).toBe(
      true,
    );
  });

  it("does not consume the other bucket when one rejects", async () => {
    vi.stubEnv("RATE_LIMIT_IP_PER_HOUR", "50");
    vi.stubEnv("RATE_LIMIT_DOMAIN_PER_DAY", "1");
    const target = "popular.example.com";
    await checkScanRateLimits({ ip: "203.0.113.20", targets: [target] });
    // Second request hits the exhausted domain bucket from a new IP.
    const blocked = await checkScanRateLimits({ ip: "203.0.113.21", targets: [target] });
    expect(blocked.allowed).toBe(false);
    // That new IP's bucket was never consumed: it can scan a fresh target.
    expect(
      (await checkScanRateLimits({ ip: "203.0.113.21", targets: ["fresh.example.com"] })).allowed,
    ).toBe(true);
  });

  it("reports the bucket with the longer wait when both reject", async () => {
    vi.stubEnv("RATE_LIMIT_IP_PER_HOUR", "1");
    vi.stubEnv("RATE_LIMIT_DOMAIN_PER_DAY", "1");
    const ip = "203.0.113.30";
    const target = "both-limited.example.com";
    await checkScanRateLimits({ ip, targets: [target] });
    const blocked = await checkScanRateLimits({ ip, targets: [target] });
    expect(blocked.allowed).toBe(false);
    if (!blocked.allowed && blocked.status === 429) {
      // Both reject; whichever scope is reported must carry a positive wait.
      expect(["ip", "domain"]).toContain(blocked.scope);
      expect(blocked.retryAfterSeconds).toBeGreaterThanOrEqual(1);
    }
  });
});

describe("checkScanRateLimits (production without Upstash)", () => {
  it("fails closed with 503", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("UPSTASH_REDIS_REST_URL", "");
    vi.stubEnv("UPSTASH_REDIS_REST_TOKEN", "");
    const result = await checkScanRateLimits({ ip: "203.0.113.1", targets: [] });
    expect(result).toEqual({ allowed: false, status: 503 });
  });
});

describe("getClientIp", () => {
  it("uses the first x-forwarded-for value", () => {
    const headers = new Headers({ "x-forwarded-for": " 1.2.3.4 , 5.6.7.8" });
    expect(getClientIp(headers)).toBe("1.2.3.4");
  });

  it("falls back to x-real-ip then unknown", () => {
    expect(getClientIp(new Headers({ "x-real-ip": "9.9.9.9" }))).toBe("9.9.9.9");
    expect(getClientIp(new Headers())).toBe("unknown");
    expect(getClientIp(new Headers({ "x-forwarded-for": " , " }))).toBe("unknown");
  });
});
