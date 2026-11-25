import { PgDialect } from "drizzle-orm/pg-core";
import { describe, expect, it } from "vitest";
import { getFindingSummary, persistFindings } from "@/lib/scanner/persist";
import { redactSecret } from "@/lib/scanner/redact";
import type { ScanFinding } from "@/lib/scanner/types";
import { mockDb } from "../helpers/mock-db";

/** Render a captured drizzle WHERE condition to { sql, params }. */
function renderWhere(condition: unknown): { sql: string; params: unknown[] } {
  return new PgDialect().sqlToQuery(condition as never);
}

/** Site-scoped persist for the pre-existing tests. */
const persistSite = (
  db: Parameters<typeof persistFindings>[0],
  scanId: string,
  findings: Parameters<typeof persistFindings>[2],
) => persistFindings(db, scanId, findings, { scope: "site" });

function finding(overrides: Partial<ScanFinding> = {}): ScanFinding {
  return {
    checkId: "site.headers.hsts",
    category: "security",
    severity: "medium",
    confidence: "high",
    title: "Missing Strict-Transport-Security header",
    evidence: "header not present",
    ...overrides,
  };
}

describe("persistFindings", () => {
  it("issues one batch containing the scoped delete and the insert", async () => {
    const { db, batches, insertedRows } = mockDb();
    await persistSite(db, "scan-1", [finding(), finding({ checkId: "other.check" })]);

    expect(batches).toHaveLength(1);
    expect(batches[0]).toHaveLength(2);
    expect(batches[0][0]).toMatchObject({ kind: "delete" });
    expect(batches[0][1]).toMatchObject({ kind: "insert" });
    expect((batches[0][1] as { rows: unknown[] }).rows).toEqual(insertedRows[0]);
    expect(insertedRows[0]).toHaveLength(2);
    expect(insertedRows[0][0]).toMatchObject({
      scanId: "scan-1",
      checkId: "site.headers.hsts",
      category: "security",
      severity: "medium",
      confidence: "high",
      evidenceRedacted: "header not present",
      location: null,
    });
  });

  it("batches only the delete when there are no findings", async () => {
    const { db, batches, calls } = mockDb();
    await persistSite(db, "scan-1", []);

    expect(batches).toHaveLength(1);
    expect(batches[0]).toHaveLength(1);
    expect(batches[0][0]).toMatchObject({ kind: "delete" });
    expect(calls).not.toContain("insert");
  });

  it("stays idempotent across retries (each call is one delete+insert batch)", async () => {
    const { db, batches } = mockDb();
    await persistSite(db, "scan-1", [finding()]);
    await persistSite(db, "scan-1", [finding(), finding({ severity: "low" })]);

    expect(batches).toHaveLength(2);
    for (const batch of batches) {
      expect(batch).toHaveLength(2);
      expect(batch[0]).toMatchObject({ kind: "delete" });
      expect(batch[1]).toMatchObject({ kind: "insert" });
    }
  });

  it("truncates title to 200 chars and evidence to 500", async () => {
    const { db, insertedRows } = mockDb();
    await persistSite(db, "scan-1", [
      finding({ title: "t".repeat(300), evidence: "x".repeat(600) }),
    ]);
    const row = insertedRows[0][0];
    expect((row.title as string).length).toBe(200);
    expect((row.evidenceRedacted as string).length).toBe(500);
  });

  it("stores location as origin + pathname, dropping query and fragment", async () => {
    const { db, insertedRows } = mockDb();
    await persistSite(db, "scan-1", [
      finding({ location: "https://example.com/some/path?token=abc#section" }),
    ]);
    expect(insertedRows[0][0].location).toBe("https://example.com/some/path");
  });

  it("truncates non-URL locations to 300 chars", async () => {
    const { db, insertedRows } = mockDb();
    await persistSite(db, "scan-1", [finding({ location: `not a url ${"y".repeat(400)}` })]);
    const location = insertedRows[0][0].location as string;
    expect(location.length).toBe(300);
    expect(location).not.toContain("?");
  });

  it("scrubs a full secret that slipped into evidence before storing", async () => {
    const { db, insertedRows } = mockDb();
    // Built at runtime so no secret-shaped literal exists in the repo.
    const leakedKey = "sk" + "_live_" + "x".repeat(24);
    await persistSite(db, "scan-1", [finding({ evidence: `leaked key ${leakedKey} in bundle` })]);
    const stored = insertedRows[0][0].evidenceRedacted as string;
    expect(stored).not.toContain(leakedKey);
    expect(stored).toContain(redactSecret(leakedKey));
  });

  it("scrubs secrets in title and location too", async () => {
    const { db, insertedRows } = mockDb();
    const leakedKey = "sk" + "_live_" + "z".repeat(24);
    await persistSite(db, "scan-1", [
      finding({
        title: `Found ${leakedKey}`,
        location: `https://example.com/${leakedKey}`,
      }),
    ]);
    const row = insertedRows[0][0];
    expect(row.title as string).not.toContain(leakedKey);
    expect(row.location as string).not.toContain(leakedKey);
  });

  it("leaves normal finding text unchanged", async () => {
    const { db, insertedRows } = mockDb();
    await persistSite(db, "scan-1", [
      finding({ title: "Missing header", evidence: "header not present" }),
    ]);
    expect(insertedRows[0][0].title).toBe("Missing header");
    expect(insertedRows[0][0].evidenceRedacted).toBe("header not present");
  });

  it("does not store a fragment of a secret that straddles the evidence cut", async () => {
    const { db, insertedRows } = mockDb();
    // Built at runtime so no secret-shaped literal exists in the repo.
    const key = "sk" + "_live_" + "q".repeat(24);
    // The key starts at index 485. A plain slice(0, 500) would keep "sk_live_" plus
    // 7 characters, which is too short for any pattern to match afterwards.
    const evidence = `${"a".repeat(484)} ${key} ${"b".repeat(100)}`;
    await persistSite(db, "scan-1", [finding({ evidence })]);
    const stored = JSON.stringify(insertedRows);
    expect(stored).not.toContain(key);
    expect(stored).not.toContain("sk_live_");
  });

  it("does not store a fragment of a secret that straddles the title cut", async () => {
    const { db, insertedRows } = mockDb();
    const key = "sk" + "_live_" + "w".repeat(24);
    // The key starts at index 185, so a plain slice(0, 200) keeps 15 characters of it.
    const title = `${"t".repeat(184)} ${key}`;
    await persistSite(db, "scan-1", [finding({ title })]);
    const stored = JSON.stringify(insertedRows);
    expect(stored).not.toContain("sk_live_");
  });

  it("caps a long URL location at 300 characters", async () => {
    const { db, insertedRows } = mockDb();
    const location = `https://example.com/${"p".repeat(500)}?token=abc`;
    await persistSite(db, "scan-1", [finding({ location })]);
    const stored = insertedRows[0][0].location as string;
    expect(stored.length).toBeLessThanOrEqual(300);
    expect(stored).not.toContain("token=abc");
  });

  it("scopes the delete to this scan and check ids starting with 'site.'", async () => {
    const { db, deleteWheres } = mockDb();
    await persistSite(db, "scan-1", [finding()]);
    const rendered = renderWhere(deleteWheres[0]);
    expect(rendered.sql).toContain("scan_id");
    expect(rendered.sql).toContain("check_id");
    expect(rendered.sql.toLowerCase()).toContain("like");
    expect(rendered.params).toContain("scan-1");
    expect(rendered.params).toContain("site.%");
  });

  it("scopes the delete to 'repo.' when persisting repo findings", async () => {
    const { db, deleteWheres, insertedRows } = mockDb();
    await persistFindings(db, "scan-1", [finding({ checkId: "repo.env.committed" })], {
      scope: "repo",
    });
    const rendered = renderWhere(deleteWheres[0]);
    expect(rendered.params).toContain("repo.%");
    expect(rendered.params).not.toContain("site.%");
    expect(insertedRows[0][0].checkId).toBe("repo.env.committed");
  });

  it("a repo persist issues a repo-scoped delete, leaving site rows untouched", async () => {
    const { db, deleteWheres, batches } = mockDb();
    // Site findings were persisted earlier by the scan-site step...
    await persistSite(db, "scan-1", [finding()]);
    // ...then the scan-repo step persists repo findings in its own batch.
    await persistFindings(db, "scan-1", [finding({ checkId: "repo.quality.basics" })], {
      scope: "repo",
    });
    expect(batches).toHaveLength(2);
    const siteDelete = renderWhere(deleteWheres[0]);
    const repoDelete = renderWhere(deleteWheres[1]);
    expect(siteDelete.params).toContain("site.%");
    expect(repoDelete.params).toContain("repo.%");
    expect(repoDelete.params).not.toContain("site.%");
  });

  it("is idempotent for the repo scope across retries", async () => {
    const { db, deleteWheres, batches } = mockDb();
    await persistFindings(db, "scan-1", [finding({ checkId: "repo.env.committed" })], {
      scope: "repo",
    });
    await persistFindings(db, "scan-1", [finding({ checkId: "repo.quality.basics" })], {
      scope: "repo",
    });
    expect(batches).toHaveLength(2);
    for (const where of deleteWheres) {
      expect(renderWhere(where).params).toContain("repo.%");
    }
  });
});

describe("getFindingSummary", () => {
  it("counts by severity and returns top non-info findings, highest first", async () => {
    const { db } = mockDb([
      { severity: "info", title: "note" },
      { severity: "low", title: "low one" },
      { severity: "critical", title: "critical one" },
      { severity: "high", title: "high one" },
      { severity: "medium", title: "medium one" },
      { severity: "high", title: "high two" },
    ]);

    const summary = await getFindingSummary(db, "scan-1");
    expect(summary.counts).toEqual({
      critical: 1,
      high: 2,
      medium: 1,
      low: 1,
      info: 1,
    });
    expect(summary.topFindings).toEqual([
      { severity: "critical", title: "critical one" },
      { severity: "high", title: "high one" },
      { severity: "high", title: "high two" },
    ]);
  });

  it("returns zero counts and no top findings for an empty scan", async () => {
    const { db } = mockDb();
    const summary = await getFindingSummary(db, "scan-1");
    expect(summary.counts).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
    expect(summary.topFindings).toEqual([]);
  });
});
