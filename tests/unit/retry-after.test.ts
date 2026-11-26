import { describe, expect, it } from "vitest";
import {
  formatCountdown,
  formatDuration,
  parseRateLimitError,
  remainingSeconds,
} from "@/lib/retry-after";

describe("formatDuration", () => {
  it("formats seconds, minutes, and hours", () => {
    expect(formatDuration(45)).toBe("45 seconds");
    expect(formatDuration(1)).toBe("1 second");
    expect(formatDuration(720)).toBe("12 minutes");
    expect(formatDuration(10_800)).toBe("3 hours");
  });

  it("rounds to the nearest unit, never shows 60 of a smaller unit, and floors at 1 second", () => {
    expect(formatDuration(0)).toBe("1 second");
    expect(formatDuration(-30)).toBe("1 second");
    expect(formatDuration(59)).toBe("59 seconds");
    expect(formatDuration(60)).toBe("1 minute");
    expect(formatDuration(89)).toBe("1 minute");
    expect(formatDuration(90)).toBe("2 minutes");
    expect(formatDuration(59.6)).toBe("1 minute");
    expect(formatDuration(3599)).toBe("1 hour");
    expect(formatDuration(3600)).toBe("1 hour");
    expect(formatDuration(5400)).toBe("2 hours");
    expect(formatDuration(86_399)).toBe("24 hours");
  });
});

describe("formatCountdown", () => {
  it("formats sub-minute and minute counts", () => {
    expect(formatCountdown(45)).toBe("45 seconds");
    expect(formatCountdown(700)).toBe("11 minutes 40 seconds");
    expect(formatCountdown(0)).toBe("0 seconds");
  });
});

describe("remainingSeconds", () => {
  it("ceils and never goes negative", () => {
    expect(remainingSeconds(61_000, 0)).toBe(61);
    expect(remainingSeconds(1_000, 500)).toBe(1);
    expect(remainingSeconds(0, 10_000)).toBe(0);
  });
});

describe("parseRateLimitError", () => {
  const valid = {
    error: "rate_limited",
    scope: "ip",
    retryAfterSeconds: 300,
    message: "You've started a lot of scans in a short time.",
  };

  it("parses a valid payload", () => {
    expect(parseRateLimitError(valid)).toEqual(valid);
    expect(parseRateLimitError({ ...valid, scope: "domain" })?.scope).toBe("domain");
  });

  it("rejects missing fields, wrong types, and wrong literals", () => {
    expect(parseRateLimitError(null)).toBeNull();
    expect(parseRateLimitError({})).toBeNull();
    expect(parseRateLimitError({ ...valid, error: "other" })).toBeNull();
    expect(parseRateLimitError({ ...valid, scope: "user" })).toBeNull();
    expect(parseRateLimitError({ ...valid, retryAfterSeconds: "300" })).toBeNull();
    expect(parseRateLimitError({ ...valid, retryAfterSeconds: 0 })).toBeNull();
    expect(parseRateLimitError({ ...valid, retryAfterSeconds: 1.5 })).toBeNull();
    expect(parseRateLimitError({ ...valid, message: 42 })).toBeNull();
  });
});
