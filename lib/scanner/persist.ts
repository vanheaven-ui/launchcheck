import { and, eq, like } from "drizzle-orm";
import type { NeonHttpDatabase } from "drizzle-orm/neon-http";
import * as schema from "@/lib/db/schema";
import { scrubSecrets } from "@/lib/scanner/scrub";
import { severityRank } from "@/lib/scanner/severity";
import type { ScanFinding, Severity } from "@/lib/scanner/types";

const { findings } = schema;

export type Db = NeonHttpDatabase<typeof schema>;

const MAX_EVIDENCE_LENGTH = 500;
const MAX_TITLE_LENGTH = 200;
const MAX_LOCATION_LENGTH = 300;
const TOP_FINDINGS_LIMIT = 3;

export type FindingSummary = {
  counts: Record<Severity, number>;
  topFindings: { severity: Severity; title: string }[];
};

/**
 * Scrub, truncate, then scrub again.
 * - The first scrub runs on the FULL text, so a secret that straddles the length
 *   cap is masked before it can be cut in half.
 * - The second scrub catches any partial match the truncation itself created.
 */
function clean(value: string, maxLength: number): string {
  return scrubSecrets(scrubSecrets(value).slice(0, maxLength));
}

/**
 * Location is stored as origin + pathname only (no query string or fragment,
 * which can carry tokens). Non-URL locations fall back to a plain truncation.
 * The result is always capped at MAX_LOCATION_LENGTH and scrubbed.
 */
function sanitizeLocation(location: string | undefined): string | null {
  if (!location) {
    return null;
  }
  let value: string;
  try {
    const url = new URL(location);
    value = `${url.origin}${url.pathname}`;
  } catch {
    value = location;
  }
  return clean(value, MAX_LOCATION_LENGTH);
}

/** Which pipeline step's findings a persist call owns. */
export type PersistScope = "site" | "repo";

/**
 * Idempotently replace a scan's findings for ONE scope in ONE batched request:
 * the delete removes only this scan's rows whose check_id starts with
 * "site." or "repo." (so the scan-site and scan-repo steps never delete each
 * other's findings), then the insert runs when there are rows. Safe to retry —
 * a retried step never produces duplicates.
 */
export async function persistFindings(
  db: Db,
  scanId: string,
  scanFindings: readonly ScanFinding[],
  options: { scope: PersistScope },
): Promise<void> {
  const rows = scanFindings.map((finding) => ({
    scanId,
    checkId: finding.checkId,
    category: finding.category,
    severity: finding.severity,
    confidence: finding.confidence,
    title: clean(finding.title, MAX_TITLE_LENGTH),
    evidenceRedacted: clean(finding.evidence, MAX_EVIDENCE_LENGTH),
    location: sanitizeLocation(finding.location),
  }));

  const deleteQuery = db
    .delete(findings)
    .where(and(eq(findings.scanId, scanId), like(findings.checkId, `${options.scope}.%`)));
  if (rows.length > 0) {
    await db.batch([deleteQuery, db.insert(findings).values(rows)]);
  } else {
    await db.batch([deleteQuery]);
  }
}

/** Severity counts plus up to 3 highest-severity non-info finding titles. */
export async function getFindingSummary(db: Db, scanId: string): Promise<FindingSummary> {
  const rows = await db
    .select({ severity: findings.severity, title: findings.title })
    .from(findings)
    .where(eq(findings.scanId, scanId));

  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const row of rows) {
    counts[row.severity] += 1;
  }

  const topFindings = rows
    .filter((row) => row.severity !== "info")
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
    .slice(0, TOP_FINDINGS_LIMIT)
    .map((row) => ({ severity: row.severity, title: row.title }));

  return { counts, topFindings };
}
