import type { GithubClient, GithubErrorCode } from "@/lib/scanner/github";
import { repoChecks } from "@/lib/scanner/repo-registry";
import { buildRepoSnapshot } from "@/lib/scanner/repo-snapshot";
import { runChecks, toScanFindings } from "@/lib/scanner/runner";
import type { Fetcher, RawFinding, RepoCheck, ScanFinding } from "@/lib/scanner/types";

export type RepoScanResult =
  | { ok: true; findings: ScanFinding[] }
  | { ok: false; reason: GithubErrorCode };

export type RepoScanOptions = {
  repoUrl: string;
  github: GithubClient;
  fetcher: Fetcher;
  checks?: readonly RepoCheck[];
};

/**
 * Snapshot the repo once, run all repo checks against it, and turn snapshot
 * notes into info findings. Never throws on check failures (runner isolates
 * them); returns the GithubError code when the repo cannot be read.
 */
export async function runRepoScan(options: RepoScanOptions): Promise<RepoScanResult> {
  const built = await buildRepoSnapshot(options.repoUrl, {
    github: options.github,
    fetcher: options.fetcher,
  });
  if (!built.ok) {
    return built;
  }

  const results = await runChecks(options.checks ?? repoChecks, { repo: built.snapshot });
  const findings = toScanFindings(results);

  for (const note of built.snapshot.notes) {
    findings.push({
      checkId: "repo.snapshot.notes",
      category: "reliability",
      severity: "info",
      confidence: "high",
      title: note,
      evidence: "snapshot_note",
    });
  }

  return { ok: true, findings };
}

/** The single info finding persisted when a repo cannot be read in `both` mode. */
export function unreadableRepoFinding(reason: GithubErrorCode): ScanFinding {
  const finding: RawFinding = {
    checkId: "repo.snapshot.notes",
    severity: "info",
    confidence: "high",
    title: "The repository could not be scanned",
    evidence: reason,
  };
  return { ...finding, category: "reliability" };
}
