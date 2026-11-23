import type { RawFinding, RepoCheck, RepoScanContext } from "@/lib/scanner/types";

const ENV_FILE_NAME = /^\.env(\..+)?$/i;
const ENV_FILE_SUFFIX = /\.env$/i;
const EXAMPLE_SUFFIX = /\.(example|sample|template|defaults|dist)$/i;
const KEY_VALUE_LINE = /^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*["']?[^\s"']+/m;
const MAX_EVIDENCE_PATHS = 5;

function basename(path: string): string {
  const index = path.lastIndexOf("/");
  return index === -1 ? path : path.slice(index + 1);
}

/** Env files committed to the repo; example/template variants are excluded. */
export function isCommittedEnvPath(path: string): boolean {
  const base = basename(path);
  if (EXAMPLE_SUFFIX.test(base)) {
    return false;
  }
  return ENV_FILE_NAME.test(base) || ENV_FILE_SUFFIX.test(base);
}

function blobUrl(ctx: RepoScanContext, path: string): string {
  const { owner, repo, sha } = ctx.repo;
  const encoded = path
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  return `https://github.com/${owner}/${repo}/blob/${sha}/${encoded}`;
}

/**
 * repo.env.committed — flags committed environment files. Critical/high when
 * at least one was fetched and contains a KEY=value line with a non-empty
 * value; high severity otherwise. Evidence lists paths only, never contents.
 */
export const envCommittedCheck: RepoCheck = {
  id: "repo.env.committed",
  category: "secrets",
  target: "repo",
  async run(ctx: RepoScanContext): Promise<RawFinding[]> {
    const { repo } = ctx;
    const envPaths = repo.tree.map((entry) => entry.path).filter(isCommittedEnvPath);
    if (envPaths.length === 0) {
      return [];
    }

    const fetched = new Map(repo.files.map((file) => [file.path, file.text]));
    const hasSecretValues = envPaths.some((path) => {
      const text = fetched.get(path);
      return text !== undefined && KEY_VALUE_LINE.test(text);
    });

    const shown = envPaths.slice(0, MAX_EVIDENCE_PATHS);
    const overflow = envPaths.length - shown.length;
    const evidence =
      `Committed environment file(s): ${shown.join(", ")}` +
      (overflow > 0 ? ` (+${overflow} more)` : "");

    return [
      {
        checkId: this.id,
        severity: hasSecretValues ? "critical" : "high",
        confidence: hasSecretValues ? "high" : "medium",
        title: "An environment file is committed to the repository",
        evidence,
        location: blobUrl(ctx, envPaths[0]),
      },
    ];
  },
};
