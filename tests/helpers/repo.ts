import type { RepoScanContext, RepoSnapshot } from "@/lib/scanner/types";
import { createFakeOsv } from "./fake-osv";

/** Minimal valid RepoSnapshot for repo-check tests; override what you need. */
export function makeRepoSnapshot(overrides: Partial<RepoSnapshot> = {}): RepoSnapshot {
  return {
    owner: "acme",
    repo: "app",
    defaultBranch: "main",
    sha: "0123456789abcdef0123456789abcdef01234567",
    treeTruncated: false,
    tree: [],
    files: [],
    notes: [],
    ...overrides,
  };
}

/** Failing fetcher: every URL returns a network error unless overridden. */
export const failingFetcher = async () => ({
  ok: false as const,
  reason: "network_error" as const,
  message: "no route",
});

/**
 * Minimal valid RepoScanContext for repo-check tests. `fetch` fails closed and
 * `osv` reports no vulnerabilities unless the test overrides them.
 */
export function makeRepoContext(
  overrides: Partial<RepoSnapshot> = {},
  context: Partial<Omit<RepoScanContext, "repo">> = {},
): RepoScanContext {
  return {
    repo: makeRepoSnapshot(overrides),
    fetch: failingFetcher,
    osv: createFakeOsv().osv,
    ...context,
  };
}
