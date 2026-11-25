import type { RepoSnapshot } from "@/lib/scanner/types";

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

export function makeRepoContext(overrides: Partial<RepoSnapshot> = {}) {
  return { repo: makeRepoSnapshot(overrides) };
}
