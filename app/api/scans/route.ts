import { and, desc, eq, isNull } from "drizzle-orm";
import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { scans } from "@/lib/db/schema";
import { inngest } from "@/lib/inngest/client";
import { checkScanRateLimits, getClientIp } from "@/lib/ratelimit";
import { formatDuration } from "@/lib/retry-after";
import {
  ANON_TOKEN_COOKIE,
  ANON_TOKEN_MAX_AGE_SECONDS,
  generateAnonToken,
  hashAnonToken,
} from "@/lib/scan-token";
import {
  hostnameFromUrl,
  parseGithubRepoUrl,
  scanRequestSchema,
} from "@/lib/scanner/validation.server";

// Node.js runtime is the default; `runtime` segment config is unavailable
// while cacheComponents is enabled in next.config.ts.

/** A completed scan this recent counts as a duplicate submission. */
const DEDUPE_WINDOW_MS = 60_000;

function errorResponse(status: number, message: string, headers?: HeadersInit) {
  return NextResponse.json({ error: message }, { status, headers });
}

function readCookie(headers: Headers, name: string): string | null {
  const header = headers.get("cookie");
  if (!header) {
    return null;
  }
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) {
      return decodeURIComponent(rest.join("="));
    }
  }
  return null;
}

type Db = ReturnType<typeof getDb>;

/**
 * Find a scan this anonymous token already created for the same targets that
 * is still active (queued/running) or completed within the last 60 seconds.
 * Returns null on any error so a dedupe lookup never blocks a scan.
 */
async function findReusableScan(
  db: Db,
  tokenHash: string,
  siteUrl: string | null,
  repoUrl: string | null,
): Promise<{ id: string } | null> {
  try {
    const rows = await db
      .select({ id: scans.id, status: scans.status, createdAt: scans.createdAt })
      .from(scans)
      .where(
        and(
          eq(scans.anonTokenHash, tokenHash),
          siteUrl === null ? isNull(scans.siteUrl) : eq(scans.siteUrl, siteUrl),
          repoUrl === null ? isNull(scans.repoUrl) : eq(scans.repoUrl, repoUrl),
        ),
      )
      .orderBy(desc(scans.createdAt));

    const cutoff = Date.now() - DEDUPE_WINDOW_MS;
    const match = rows.find(
      (row) =>
        row.status === "queued" ||
        row.status === "running" ||
        (row.status === "completed" && row.createdAt.getTime() > cutoff),
    );
    return match ? { id: match.id } : null;
  } catch {
    return null;
  }
}

/** Per-day rate-limit bucket keys: site hostname, or github.com/<owner>/<repo>. */
function rateLimitTargets(data: {
  mode: "site" | "repo" | "both";
  siteUrl?: string;
  repoUrl?: string;
}): string[] {
  const targets: string[] = [];
  if (data.mode !== "repo") {
    const host = hostnameFromUrl(data.siteUrl);
    if (host) {
      targets.push(host);
    }
  }
  if (data.mode !== "site" && data.repoUrl) {
    const parsed = parseGithubRepoUrl(data.repoUrl);
    if (parsed) {
      targets.push(`github.com/${parsed.owner}/${parsed.repo}`.toLowerCase());
    }
  }
  return targets;
}

function rateLimitedResponse(decision: { scope: "ip" | "domain"; retryAfterSeconds: number }) {
  const duration = formatDuration(decision.retryAfterSeconds);
  const message =
    decision.scope === "ip"
      ? `You've started a lot of scans in a short time. You can run another in about ${duration}.`
      : `This site (or repository) has been scanned many times today. Please try again in about ${duration}.`;
  return NextResponse.json(
    {
      error: "rate_limited",
      scope: decision.scope,
      retryAfterSeconds: decision.retryAfterSeconds,
      message,
    },
    {
      status: 429,
      headers: {
        "Retry-After": String(decision.retryAfterSeconds),
        "Cache-Control": "no-store",
      },
    },
  );
}

export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse(400, "Invalid request body.");
  }

  const parsed = scanRequestSchema.safeParse(body);
  if (!parsed.success) {
    return errorResponse(400, "Invalid scan request.");
  }
  const data = parsed.data;

  // Defensive: validation already guarantees this, but an unparseable repo
  // URL must never fall through to a shared bucket or a scan.
  if (data.mode !== "site" && data.repoUrl && !parseGithubRepoUrl(data.repoUrl)) {
    return errorResponse(400, "Invalid scan request.");
  }

  // URLs are normalized exactly as they will be stored, so dedupe compares
  // like with like.
  const siteUrl = data.mode === "repo" ? null : data.siteUrl || null;
  const repoUrl = data.mode === "site" ? null : data.repoUrl || null;

  const db = getDb();

  // De-duplicate before touching the rate limiter: a resubmission of the same
  // scan returns the existing row without consuming a token or new resources.
  const cookieToken = readCookie(request.headers, ANON_TOKEN_COOKIE);
  if (cookieToken) {
    const reusable = await findReusableScan(db, hashAnonToken(cookieToken), siteUrl, repoUrl);
    if (reusable) {
      return NextResponse.json({ id: reusable.id, reused: true }, { status: 200 });
    }
  }

  const ip = getClientIp(request.headers);
  const rateLimit = await checkScanRateLimits({ ip, targets: rateLimitTargets(data) });
  if (!rateLimit.allowed) {
    if (rateLimit.status === 429) {
      return rateLimitedResponse(rateLimit);
    }
    return NextResponse.json(
      {
        error: "service_unavailable",
        message: "Scanning is temporarily unavailable. Please try again in a moment.",
      },
      { status: 503, headers: { "Retry-After": "30", "Cache-Control": "no-store" } },
    );
  }

  const token = generateAnonToken();
  const tokenHash = hashAnonToken(token);

  let scanId: string;
  try {
    const [row] = await db
      .insert(scans)
      .values({
        siteUrl,
        repoUrl,
        anonTokenHash: tokenHash,
        status: "queued",
      })
      .returning({ id: scans.id });
    scanId = row.id;
  } catch {
    return errorResponse(500, "Something went wrong. Please try again.");
  }

  try {
    await inngest.send({ name: "scan/requested", data: { scanId } });
  } catch {
    try {
      await db
        .update(scans)
        .set({ status: "failed", error: "enqueue_failed" })
        .where(eq(scans.id, scanId));
    } catch {
      // Best effort: the row already exists; the failure is logged by Inngest client.
    }
    return errorResponse(500, "Something went wrong. Please try again.");
  }

  const response = NextResponse.json({ id: scanId }, { status: 201 });
  response.cookies.set({
    name: ANON_TOKEN_COOKIE,
    value: token,
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: ANON_TOKEN_MAX_AGE_SECONDS,
  });
  return response;
}
