import { z } from "zod";

/**
 * Pure helpers for rate-limit UX. Safe to import from client components:
 * no Node APIs, no side effects.
 */

/** Body contract returned by POST /api/scans on HTTP 429. */
export const rateLimitErrorSchema = z.object({
  error: z.literal("rate_limited"),
  scope: z.enum(["ip", "domain"]),
  retryAfterSeconds: z.number().int().positive(),
  message: z.string().min(1),
});

export type RateLimitErrorPayload = z.infer<typeof rateLimitErrorSchema>;

/** Parse an untrusted 429 body; returns null when it does not match. */
export function parseRateLimitError(body: unknown): RateLimitErrorPayload | null {
  const parsed = rateLimitErrorSchema.safeParse(body);
  return parsed.success ? parsed.data : null;
}

/**
 * Human-readable wait time for messages, e.g. "45 seconds", "12 minutes",
 * "3 hours". Rounds to the nearest unit, minimum "1 second".
 */
export function formatDuration(totalSeconds: number): string {
  const seconds = Math.max(1, Math.round(totalSeconds));
  if (seconds < 60) {
    return `${seconds} second${seconds === 1 ? "" : "s"}`;
  }
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) {
    return `${minutes} minute${minutes === 1 ? "" : "s"}`;
  }
  const hours = Math.round(seconds / 3600);
  return `${hours} hour${hours === 1 ? "" : "s"}`;
}

/**
 * Whole seconds remaining until `retryAtMs`, never negative. Used for the
 * submit-button countdown; the Retry-After value stays the source of truth.
 */
export function remainingSeconds(retryAtMs: number, nowMs: number = Date.now()): number {
  return Math.max(0, Math.ceil((retryAtMs - nowMs) / 1000));
}

/** "11 minutes 40 seconds" style countdown text (minutes omitted under 60s). */
export function formatCountdown(totalSeconds: number): string {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  const minutes = Math.floor(seconds / 60);
  const secs = seconds % 60;
  if (minutes === 0) {
    return `${secs} second${secs === 1 ? "" : "s"}`;
  }
  return `${minutes} minute${minutes === 1 ? "" : "s"} ${secs} second${secs === 1 ? "" : "s"}`;
}
