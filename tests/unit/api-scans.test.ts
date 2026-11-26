import { createHash } from "node:crypto";
import { PgDialect } from "drizzle-orm/pg-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { scans } from "@/lib/db/schema";

const SCAN_ID = "11111111-2222-3333-4444-555555555555";
const EXISTING_ID = "99999999-8888-7777-6666-555555555555";

const mocks = vi.hoisted(() => ({
  inserted: [] as Record<string, unknown>[],
  updated: [] as Record<string, unknown>[],
  inngestSend: vi.fn(),
  /** Rows returned by the dedupe select on the scans table. */
  scanRows: [] as { id: string; status: string; createdAt: Date }[],
  /** WHERE conditions passed to each select().where() call. */
  selectWheres: [] as unknown[],
}));

vi.mock("@/lib/db", () => ({
  getDb: () => ({
    insert: () => ({
      values: (values: Record<string, unknown>) => {
        mocks.inserted.push(values);
        return { returning: async () => [{ id: SCAN_ID }] };
      },
    }),
    update: () => ({
      set: (values: Record<string, unknown>) => {
        mocks.updated.push(values);
        return { where: async () => undefined };
      },
    }),
    select: () => ({
      from: (table: unknown) => ({
        where: (condition: unknown) => {
          mocks.selectWheres.push(condition);
          return {
            orderBy: async () => {
              if (table === scans) {
                return mocks.scanRows;
              }
              return [];
            },
          };
        },
      }),
    }),
  }),
}));

vi.mock("@/lib/inngest/client", () => ({
  inngest: { send: mocks.inngestSend },
}));

import { POST } from "@/app/api/scans/route";
import { ANON_TOKEN_COOKIE, generateAnonToken, hashAnonToken } from "@/lib/scan-token";

const VALID_BODY = {
  mode: "site",
  siteUrl: "https://example.com",
  repoUrl: "",
  acceptedOwnership: true,
};

function makeRequest(body: unknown, ip: string, cookieToken?: string) {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "x-forwarded-for": ip,
  };
  if (cookieToken) {
    headers.cookie = `${ANON_TOKEN_COOKIE}=${cookieToken}`;
  }
  return new Request("http://localhost/api/scans", {
    method: "POST",
    headers,
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

function setCookieHeader(response: Response): string {
  return response.headers.get("set-cookie") ?? "";
}

function dedupeRow(
  overrides: Partial<{
    id: string;
    status: string;
    createdAt: Date;
    siteUrl: string | null;
    repoUrl: string | null;
  }> = {},
) {
  return {
    id: EXISTING_ID,
    status: "queued",
    createdAt: new Date(),
    ...overrides,
  };
}

beforeEach(() => {
  mocks.inserted.length = 0;
  mocks.updated.length = 0;
  mocks.scanRows.length = 0;
  mocks.selectWheres.length = 0;
  mocks.inngestSend.mockReset();
  mocks.inngestSend.mockResolvedValue({ ids: ["evt_1"] });
  vi.stubEnv("UPSTASH_REDIS_REST_URL", "");
  vi.stubEnv("UPSTASH_REDIS_REST_TOKEN", "");
  vi.stubEnv("RATE_LIMIT_IP_PER_HOUR", "100");
  vi.stubEnv("RATE_LIMIT_DOMAIN_PER_DAY", "100");
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("POST /api/scans", () => {
  it("creates a scan, sets a hashed anon cookie, and sends the Inngest event", async () => {
    const response = await POST(makeRequest(VALID_BODY, "203.0.113.50"));

    expect(response.status).toBe(201);
    expect(await response.json()).toEqual({ id: SCAN_ID });

    expect(mocks.inngestSend).toHaveBeenCalledWith({
      name: "scan/requested",
      data: { scanId: SCAN_ID },
    });

    expect(mocks.inserted).toHaveLength(1);
    const row = mocks.inserted[0];
    expect(row.siteUrl).toBe("https://example.com");
    expect(row.repoUrl).toBeNull();
    expect(row.status).toBe("queued");

    const cookie = setCookieHeader(response);
    expect(cookie).toContain("anon_token=");
    expect(cookie.toLowerCase()).toContain("httponly");
    expect(cookie.toLowerCase()).toContain("samesite=lax");

    const tokenMatch = /anon_token=([^;]+)/.exec(cookie);
    expect(tokenMatch).not.toBeNull();
    const rawToken = tokenMatch?.[1] ?? "";
    const expectedHash = createHash("sha256").update(decodeURIComponent(rawToken)).digest("hex");

    // Only the SHA-256 hash is stored; the raw token never touches the DB row.
    expect(row.anonTokenHash).toBe(expectedHash);
    expect(JSON.stringify(row)).not.toContain(rawToken);
  });

  it("rejects a malformed JSON body without touching the limiter or db", async () => {
    const response = await POST(makeRequest("{not json", "203.0.113.51"));
    expect(response.status).toBe(400);
    expect(mocks.inserted).toHaveLength(0);
    expect(mocks.scanRows).toHaveLength(0);
  });

  it("rejects an invalid body without echoing input", async () => {
    const response = await POST(
      makeRequest({ ...VALID_BODY, siteUrl: "http://localhost:3000" }, "203.0.113.52"),
    );
    expect(response.status).toBe(400);
    const text = await response.text();
    expect(text).not.toContain("localhost");
    expect(mocks.inserted).toHaveLength(0);
  });

  it("rejects missing ownership confirmation", async () => {
    const response = await POST(
      makeRequest({ ...VALID_BODY, acceptedOwnership: false }, "203.0.113.53"),
    );
    expect(response.status).toBe(400);
    expect(mocks.inserted).toHaveLength(0);
    expect(mocks.inngestSend).not.toHaveBeenCalled();
  });

  it("returns 429 with Retry-After, scope, and a calm message when limited", async () => {
    vi.stubEnv("RATE_LIMIT_IP_PER_HOUR", "1");
    const ip = "203.0.113.60";
    const first = await POST(makeRequest(VALID_BODY, ip));
    expect(first.status).toBe(201);

    const blocked = await POST(makeRequest(VALID_BODY, ip));
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get("retry-after")).toBeTruthy();
    expect(blocked.headers.get("cache-control")).toBe("no-store");
    const body = await blocked.json();
    expect(body.error).toBe("rate_limited");
    expect(body.scope).toBe("ip");
    expect(body.retryAfterSeconds).toBe(Number(blocked.headers.get("retry-after")));
    expect(body.message).toContain("in about");
    expect(JSON.stringify(body)).not.toContain(ip);
    expect(mocks.inserted).toHaveLength(1);
  });

  it("rate limits per repo target, not a shared github.com bucket", async () => {
    vi.stubEnv("RATE_LIMIT_IP_PER_HOUR", "50");
    vi.stubEnv("RATE_LIMIT_DOMAIN_PER_DAY", "1");
    const repoBody = {
      mode: "repo",
      siteUrl: "",
      repoUrl: "https://github.com/acme/app",
      acceptedOwnership: true,
    };
    expect((await POST(makeRequest(repoBody, "198.51.100.1"))).status).toBe(201);
    // Same repo from a different IP is blocked.
    const blocked = await POST(makeRequest(repoBody, "198.51.100.2"));
    expect(blocked.status).toBe(429);
    expect((await blocked.json()).scope).toBe("domain");
    // A different repo is unaffected.
    const other = await POST(
      makeRequest({ ...repoBody, repoUrl: "https://github.com/acme/other" }, "198.51.100.3"),
    );
    expect(other.status).toBe(201);
  });

  it("returns 500 and marks the scan failed when Inngest send fails", async () => {
    mocks.inngestSend.mockRejectedValueOnce(new Error("inngest down"));
    const response = await POST(makeRequest(VALID_BODY, "203.0.113.70"));
    expect(response.status).toBe(500);
    expect(mocks.updated[0]).toMatchObject({ status: "failed" });
  });
});

describe("POST /api/scans de-duplication", () => {
  it("reuses a queued scan for the same token and targets", async () => {
    const token = generateAnonToken();
    mocks.scanRows.push(dedupeRow());
    const response = await POST(makeRequest(VALID_BODY, "203.0.113.80", token));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ id: EXISTING_ID, reused: true });
    expect(mocks.inserted).toHaveLength(0);
    expect(mocks.inngestSend).not.toHaveBeenCalled();
  });

  it("reuses running and recently-completed scans", async () => {
    const token = generateAnonToken();
    for (const status of ["running", "completed"]) {
      mocks.scanRows.length = 0;
      mocks.scanRows.push(dedupeRow({ status }));
      const response = await POST(
        makeRequest(VALID_BODY, `203.0.113.${status === "running" ? 81 : 82}`, token),
      );
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ id: EXISTING_ID, reused: true });
    }
    expect(mocks.inserted).toHaveLength(0);
  });

  it("does not reuse failed scans or completions older than 60 seconds", async () => {
    const token = generateAnonToken();
    mocks.scanRows.push(dedupeRow({ status: "failed" }));
    const failed = await POST(makeRequest(VALID_BODY, "203.0.113.83", token));
    expect(failed.status).toBe(201);

    mocks.scanRows.length = 0;
    mocks.scanRows.push(
      dedupeRow({ status: "completed", createdAt: new Date(Date.now() - 61_000) }),
    );
    const stale = await POST(makeRequest(VALID_BODY, "203.0.113.84", token));
    expect(stale.status).toBe(201);
    expect(mocks.inserted).toHaveLength(2);
  });

  it("scopes the dedupe query to the cookie token hash and both URLs", async () => {
    const token = generateAnonToken();
    mocks.scanRows.push(dedupeRow());
    await POST(makeRequest(VALID_BODY, "203.0.113.85", token));

    // The mock cannot evaluate the WHERE clause, so compile it and check the
    // bound parameters: a different token, URL, or mode cannot match.
    const dialect = new PgDialect();
    const condition = mocks.selectWheres.at(-1) as Parameters<typeof dialect.sqlToQuery>[0];
    const query = dialect.sqlToQuery(condition);
    expect(query.params).toContain(hashAnonToken(token));
    expect(query.params).toContain("https://example.com");
    expect(query.sql).toContain("anon_token_hash");
    expect(query.sql).toContain("site_url");
    expect(query.sql).toContain("repo_url");
  });

  it("does not reuse when the DB finds no matching scan (other token, URL, or mode)", async () => {
    // With a different token/URL/mode the WHERE clause excludes every row, so
    // the select returns nothing — emulated here by an empty result set.
    const response = await POST(makeRequest(VALID_BODY, "203.0.113.86", generateAnonToken()));
    expect(response.status).toBe(201);
    expect(mocks.inserted).toHaveLength(1);
  });

  it("never reuses a scan when no anon cookie is present", async () => {
    mocks.scanRows.push(dedupeRow());
    const response = await POST(makeRequest(VALID_BODY, "203.0.113.87"));
    expect(response.status).toBe(201);
    expect(mocks.inserted).toHaveLength(1);
  });
});

describe("POST /api/scans unavailable store", () => {
  it("returns 503 with Retry-After when the limiter store is missing in production", async () => {
    vi.stubEnv("NODE_ENV", "production");
    const response = await POST(makeRequest(VALID_BODY, "203.0.113.90"));
    expect(response.status).toBe(503);
    expect(response.headers.get("retry-after")).toBe("30");
    const body = await response.json();
    expect(body.message).toContain("temporarily unavailable");
    expect(mocks.inserted).toHaveLength(0);
  });
});
