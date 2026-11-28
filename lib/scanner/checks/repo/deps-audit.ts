import { parseLockfile } from "@/lib/scanner/lockfiles";
import { OsvError, type OsvSeverity } from "@/lib/scanner/osv";
import type { RawFinding, RepoCheck, RepoScanContext, Severity } from "@/lib/scanner/types";

/**
 * repo.deps.audit — parses the repo's root lockfile and queries OSV for known
 * vulnerabilities. Emits one finding per severity tier present, plus info
 * findings for every skipped/degraded path. Never throws.
 */

const LOCKFILE_CANDIDATES = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"];
const MAX_LOCKFILE_BYTES = 2 * 1024 * 1024;
const MAX_PACKAGES = 1500;
const MAX_DETAIL_IDS = 50;
const DETAIL_CONCURRENCY = 5;
const BUDGET_MS = 15_000;
const MAX_EVIDENCE_ENTRIES = 5;

const TIER_ORDER: OsvSeverity[] = ["critical", "high", "medium", "low"];

function rawFileUrl(ctx: RepoScanContext, path: string): string {
  const { owner, repo, sha } = ctx.repo;
  const encoded = path
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  return `https://raw.githubusercontent.com/${owner}/${repo}/${sha}/${encoded}`;
}

function blobUrl(ctx: RepoScanContext, path: string): string {
  const { owner, repo, sha } = ctx.repo;
  const encoded = path
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  return `https://github.com/${owner}/${repo}/blob/${sha}/${encoded}`;
}

function infoFinding(
  ctx: RepoScanContext,
  lockfilePath: string | null,
  title: string,
  evidence: string,
): RawFinding {
  return {
    checkId: "repo.deps.audit",
    severity: "info",
    confidence: "high",
    title,
    evidence,
    ...(lockfilePath ? { location: blobUrl(ctx, lockfilePath) } : {}),
  };
}

function evidenceFor(entries: string[]): string {
  const shown = entries.slice(0, MAX_EVIDENCE_ENTRIES);
  const rest = entries.length - shown.length;
  return shown.join("; ") + (rest > 0 ? `; and ${rest} more` : "");
}

export const depsAuditCheck: RepoCheck = {
  id: "repo.deps.audit",
  category: "security",
  target: "repo",
  timeoutMs: 20_000,
  async run(ctx: RepoScanContext): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    const now = ctx.now ?? Date.now;
    const deadline = now() + BUDGET_MS;

    try {
      // One root-level lockfile, in priority order.
      const treeByPath = new Map(ctx.repo.tree.map((entry) => [entry.path, entry]));
      const lockfilePath = LOCKFILE_CANDIDATES.find((name) => treeByPath.has(name));
      if (!lockfilePath) {
        return [];
      }
      const location = blobUrl(ctx, lockfilePath);
      const treeEntry = treeByPath.get(lockfilePath);

      const skip = (title: string, evidence: string) => {
        findings.push({
          checkId: this.id,
          severity: "info",
          confidence: "high",
          title,
          evidence,
          location,
        });
      };

      if (
        treeEntry?.size !== null &&
        treeEntry?.size !== undefined &&
        treeEntry.size > MAX_LOCKFILE_BYTES
      ) {
        skip("The lockfile was too large to audit", "lockfile_exceeds_2mb");
        return findings;
      }
      if (now() >= deadline) {
        skip("The dependency audit ran out of time", "audit_budget_exhausted");
        return findings;
      }

      const res = await ctx.fetch(rawFileUrl(ctx, lockfilePath));
      if (!res.ok || res.status >= 400) {
        skip("The lockfile could not be fetched", "lockfile_fetch_failed");
        return findings;
      }
      if (res.truncated || res.body.length > MAX_LOCKFILE_BYTES) {
        skip("The lockfile was too large to audit", "lockfile_exceeds_2mb");
        return findings;
      }

      const parsed = parseLockfile(lockfilePath, res.body.toString("utf8"));
      if (!parsed.ok) {
        skip(
          parsed.reason === "unsupported"
            ? "This lockfile format is not supported yet"
            : "The lockfile could not be parsed",
          `lockfile_${parsed.reason}`,
        );
        return findings;
      }

      const packages = parsed.packages.slice(0, MAX_PACKAGES);
      const skippedPackages = parsed.packages.length - packages.length;
      if (packages.length === 0) {
        return findings;
      }

      let vulnIdsPerPackage: string[][];
      try {
        vulnIdsPerPackage = await ctx.osv.queryBatch(packages);
      } catch (error) {
        if (error instanceof OsvError) {
          skip("The vulnerability database was unavailable", "osv_unavailable");
          return findings;
        }
        throw error;
      }

      // Distinct ids, in first-seen order.
      const distinctIds: string[] = [];
      const seenIds = new Set<string>();
      for (const ids of vulnIdsPerPackage) {
        for (const id of ids) {
          if (!seenIds.has(id)) {
            seenIds.add(id);
            distinctIds.push(id);
          }
        }
      }
      if (distinctIds.length === 0) {
        if (skippedPackages > 0) {
          skip(
            "Some packages were skipped by the audit limit",
            `${skippedPackages} package(s) skipped by the ${MAX_PACKAGES}-package cap`,
          );
        }
        return findings;
      }

      // Fetch advisory details for at most MAX_DETAIL_IDS ids, 5 at a time.
      // Ids beyond the cap, null results, and errors all count as unscored.
      const detailIds = distinctIds.slice(0, MAX_DETAIL_IDS);
      const unscoredCount = distinctIds.length - detailIds.length;
      const severityById = new Map<string, OsvSeverity | undefined>();
      const scored = new Set<string>();

      for (let i = 0; i < detailIds.length; i += DETAIL_CONCURRENCY) {
        if (now() >= deadline) {
          break;
        }
        const chunk = detailIds.slice(i, i + DETAIL_CONCURRENCY);
        const details = await Promise.all(
          chunk.map(async (id) => {
            try {
              return await ctx.osv.getVuln(id);
            } catch {
              return null;
            }
          }),
        );
        for (let j = 0; j < chunk.length; j++) {
          const id = chunk[j];
          const detail = details[j];
          if (detail === null || detail === undefined) {
            continue; // unscored
          }
          scored.add(id);
          severityById.set(id, detail.severity);
        }
      }

      const trulyUnscored = unscoredCount + detailIds.filter((id) => !scored.has(id)).length;

      // Group packages by severity tier (a package counts once per tier).
      const entriesByTier = new Map<OsvSeverity, Map<string, string>>();
      const unknownPackages = new Map<string, string>();
      for (let i = 0; i < packages.length; i++) {
        const pkg = packages[i];
        const pkgKey = `${pkg.name}@${pkg.version}`;
        const tierIds = new Map<OsvSeverity, string>();
        let unknownId: string | undefined;
        for (const id of vulnIdsPerPackage[i] ?? []) {
          const severity = scored.has(id) ? severityById.get(id) : undefined;
          if (severity === undefined) {
            unknownId ??= id;
          } else if (!tierIds.has(severity)) {
            tierIds.set(severity, id);
          }
        }
        for (const [tier, id] of tierIds) {
          let entries = entriesByTier.get(tier);
          if (!entries) {
            entries = new Map();
            entriesByTier.set(tier, entries);
          }
          if (!entries.has(pkgKey)) {
            entries.set(pkgKey, `${pkgKey} (${id})`);
          }
        }
        if (unknownId !== undefined) {
          unknownPackages.set(pkgKey, `${pkgKey} (${unknownId})`);
        }
      }

      for (const tier of TIER_ORDER) {
        const entries = entriesByTier.get(tier);
        if (!entries || entries.size === 0) {
          continue;
        }
        const list = [...entries.values()];
        findings.push({
          checkId: this.id,
          severity: tier as Severity,
          confidence: "high",
          title: `${entries.size} dependencies have known ${tier} vulnerabilities`,
          evidence: evidenceFor(list),
          location,
        });
      }

      if (unknownPackages.size > 0) {
        const list = [...unknownPackages.values()];
        findings.push({
          checkId: this.id,
          severity: "medium",
          confidence: "low",
          title: `${unknownPackages.size} dependencies have vulnerabilities with unknown severity (possible issue)`,
          evidence: evidenceFor(list),
          location,
        });
      }

      if (skippedPackages > 0) {
        skip(
          "Some packages were skipped by the audit limit",
          `${skippedPackages} package(s) skipped by the ${MAX_PACKAGES}-package cap`,
        );
      }
      if (trulyUnscored > 0) {
        skip(
          "Some vulnerability details could not be scored",
          `${trulyUnscored} vulnerability id(s) were not scored`,
        );
      }
      return findings;
    } catch {
      return [infoFinding(ctx, null, "The dependency audit could not complete", "audit_failed")];
    }
  },
};
