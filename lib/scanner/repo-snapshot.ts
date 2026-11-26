import type { GithubClient, GithubErrorCode } from "@/lib/scanner/github";
import { GithubError } from "@/lib/scanner/github";
import type { Fetcher, RepoFile, RepoSnapshot, RepoTreeEntry } from "@/lib/scanner/types";
import { parseGithubRepoUrl } from "@/lib/scanner/validation";

/**
 * Repo snapshot builder (Phase 3A). Reads the repo metadata and file tree via
 * the injected GithubClient, then fetches selected text files from
 * raw.githubusercontent.com through the injected fetcher (production:
 * safeFetch). Never throws; budget exhaustion becomes notes, not failures.
 */

const MAX_FILES = 300;
const MAX_FILE_BYTES = 200 * 1024;
const MAX_TOTAL_BYTES = 15 * 1024 * 1024;
const FETCH_CONCURRENCY = 6;
const DEFAULT_DEADLINE_MS = 25_000;

/** Directories whose contents are never useful scan input. */
const SKIPPED_DIRS = new Set([
  "node_modules",
  "dist",
  "build",
  ".next",
  "vendor",
  ".git",
  "coverage",
]);

const LOCKFILE_NAMES = new Set([
  "pnpm-lock.yaml",
  "package-lock.json",
  "yarn.lock",
  "bun.lockb",
  "cargo.lock",
  "poetry.lock",
  "gemfile.lock",
  "composer.lock",
]);

const BINARY_EXTENSIONS = new Set([
  "png",
  "jpg",
  "jpeg",
  "gif",
  "webp",
  "ico",
  "pdf",
  "zip",
  "gz",
  "tar",
  "mp3",
  "mp4",
  "mov",
  "woff",
  "woff2",
  "ttf",
  "otf",
  "eot",
  "exe",
  "dll",
  "so",
  "wasm",
]);

/** First path segments that mark application source worth fetching early. */
const PRIORITY_DIRS = new Set([
  "app",
  "src",
  "pages",
  "lib",
  "api",
  "supabase",
  "apps",
  "packages",
]);
const CONFIG_FILE_RE = /\.(json|toml|ya?ml|sql)$/;

export type RepoSnapshotOptions = {
  github: GithubClient;
  fetcher: Fetcher;
  /** Injectable clock for tests. */
  now?: () => number;
  deadlineMs?: number;
};

export type RepoSnapshotResult =
  | { ok: true; snapshot: RepoSnapshot }
  | { ok: false; reason: GithubErrorCode };

function basename(path: string): string {
  const index = path.lastIndexOf("/");
  return index === -1 ? path : path.slice(index + 1);
}

/** True when the path should be skipped for content fetching. */
function isSkippedPath(path: string): boolean {
  const segments = path.split("/");
  const base = basename(path).toLowerCase();
  if (segments.some((segment) => SKIPPED_DIRS.has(segment.toLowerCase()))) {
    return true;
  }
  if (LOCKFILE_NAMES.has(base)) {
    return true;
  }
  if (base.endsWith(".min.js") || base.endsWith(".map")) {
    return true;
  }
  const dot = base.lastIndexOf(".");
  if (dot === -1) {
    return false;
  }
  return BINARY_EXTENSIONS.has(base.slice(dot + 1));
}

/** Lower tier number = fetched earlier. */
function priorityTier(path: string): number {
  const segments = path.split("/");
  const base = basename(path).toLowerCase();
  if (base.startsWith(".env")) {
    return 0;
  }
  // Config files are top priority only near the root (<=2 segments) or under
  // supabase/, so deep locale/data JSON cannot starve application source.
  if (
    CONFIG_FILE_RE.test(base) &&
    (segments.length <= 2 || segments[0]?.toLowerCase() === "supabase")
  ) {
    return 0;
  }
  const first = segments[0]?.toLowerCase() ?? "";
  if (PRIORITY_DIRS.has(first)) {
    return 1;
  }
  return 2;
}

function compareFetchOrder(a: string, b: string): number {
  const tierDiff = priorityTier(a) - priorityTier(b);
  if (tierDiff !== 0) {
    return tierDiff;
  }
  const depthDiff = a.split("/").length - b.split("/").length;
  if (depthDiff !== 0) {
    return depthDiff;
  }
  return a < b ? -1 : a > b ? 1 : 0;
}

function rawFileUrl(owner: string, repo: string, sha: string, path: string): string {
  const encodedPath = path
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  return `https://raw.githubusercontent.com/${owner}/${repo}/${sha}/${encodedPath}`;
}

function toFailure(reason: GithubErrorCode): RepoSnapshotResult {
  return { ok: false, reason };
}

/**
 * Parse a strict public GitHub repo URL (https://github.com/<owner>/<repo>),
 * reusing the same rules as the scan-request validation. Returns null when
 * the URL does not match.
 */
export function parseRepoUrl(url: string): { owner: string; repo: string } | null {
  return parseGithubRepoUrl(url);
}

/**
 * Build a RepoSnapshot under the Phase 3A budgets: at most 300 files, 200 KB
 * per file, 15 MB total, concurrency 6, and a 25-second deadline checked
 * before each fetch. Never throws.
 */
export async function buildRepoSnapshot(
  repoUrl: string,
  options: RepoSnapshotOptions,
): Promise<RepoSnapshotResult> {
  const { github, fetcher } = options;
  const now = options.now ?? Date.now;
  const deadlineMs = options.deadlineMs ?? DEFAULT_DEADLINE_MS;
  const deadline = now() + deadlineMs;
  const notes: string[] = [];

  const parsed = parseRepoUrl(repoUrl);
  if (!parsed) {
    return toFailure("repo_unreachable");
  }
  const { owner, repo } = parsed;

  try {
    const info = await github.getRepo(owner, repo);
    const treeResult = await github.getTree(owner, repo, info.defaultBranch);

    if (treeResult.truncated) {
      notes.push("The repository file tree was truncated by GitHub; some files may be missing.");
    }

    // snapshot.tree keeps every blob (checks need the full listing, including
    // files we will not fetch).
    const tree: RepoTreeEntry[] = treeResult.entries
      .filter((entry) => entry.type === "blob")
      .map((entry) => ({ path: entry.path, size: entry.size }));

    let skippedOverSize = 0;
    const candidates: string[] = [];
    for (const entry of treeResult.entries) {
      if (entry.type !== "blob") {
        continue;
      }
      if (isSkippedPath(entry.path)) {
        continue;
      }
      if (entry.size !== null && entry.size > MAX_FILE_BYTES) {
        skippedOverSize += 1;
        continue;
      }
      candidates.push(entry.path);
    }
    if (skippedOverSize > 0) {
      notes.push(
        `Skipped ${skippedOverSize} file(s) larger than ${Math.round(MAX_FILE_BYTES / 1024)} KB.`,
      );
    }

    candidates.sort(compareFetchOrder);
    const queued = candidates.slice(0, MAX_FILES);
    if (candidates.length > MAX_FILES) {
      notes.push(
        `Skipped ${candidates.length - MAX_FILES} file(s): the ${MAX_FILES}-file limit was reached.`,
      );
    }

    const files: RepoFile[] = [];
    let fetchFailures = 0;
    let index = 0;
    // Shared byte counter; workers may overshoot by one in-flight batch,
    // which is acceptable for a budget guard (same approach as the site snapshot).
    let totalBytes = 0;
    let hitDeadline = false;
    let hitByteBudget = false;

    const worker = async () => {
      while (index < queued.length) {
        if (now() >= deadline) {
          hitDeadline = true;
          return;
        }
        if (totalBytes >= MAX_TOTAL_BYTES) {
          hitByteBudget = true;
          return;
        }
        const path = queued[index];
        index += 1;
        try {
          const res = await fetcher(rawFileUrl(owner, repo, info.headSha, path));
          if (!res.ok || res.status >= 400) {
            fetchFailures += 1;
            continue;
          }
          let body = res.body;
          let truncated = res.truncated;
          if (body.length > MAX_FILE_BYTES) {
            body = body.subarray(0, MAX_FILE_BYTES);
            truncated = true;
          }
          totalBytes += body.length;
          files.push({ path, text: body.toString("utf8"), truncated });
        } catch {
          fetchFailures += 1;
        }
      }
    };

    await Promise.all(
      Array.from({ length: Math.min(FETCH_CONCURRENCY, queued.length) }, () => worker()),
    );

    // Keep fetch-priority order regardless of which worker finished first.
    files.sort((a, b) => queued.indexOf(a.path) - queued.indexOf(b.path));

    const skippedByBudget = queued.length - index;
    if (skippedByBudget > 0) {
      const reasons: string[] = [];
      if (hitDeadline) {
        reasons.push(`the ${Math.round(deadlineMs / 1000)}s scan budget was reached`);
      }
      if (hitByteBudget) {
        reasons.push("the 15 MB download budget was reached");
      }
      notes.push(
        `Skipped ${skippedByBudget} file(s): ${reasons.join(" and ") || "a scan budget was reached"}.`,
      );
    }
    if (fetchFailures > 0) {
      notes.push(`Skipped ${fetchFailures} file(s) that could not be fetched.`);
    }

    const snapshot: RepoSnapshot = {
      owner,
      repo,
      defaultBranch: info.defaultBranch,
      sha: info.headSha,
      treeTruncated: treeResult.truncated,
      tree,
      files,
      notes,
    };
    return { ok: true, snapshot };
  } catch (error) {
    if (error instanceof GithubError) {
      return toFailure(error.code);
    }
    return toFailure("repo_unreachable");
  }
}
