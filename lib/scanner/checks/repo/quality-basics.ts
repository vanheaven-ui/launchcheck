import type { RawFinding, RepoCheck, RepoScanContext } from "@/lib/scanner/types";

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

const TEST_FILE_RE = /\.(test|spec)\.[^./]+$/i;
const TEST_SCRIPT_RE = /"scripts"\s*:\s*\{[^}]*"test"\s*:/;

function basename(path: string): string {
  const index = path.lastIndexOf("/");
  return index === -1 ? path : path.slice(index + 1);
}

function dirName(path: string): string {
  const index = path.lastIndexOf("/");
  return index === -1 ? "" : path.slice(0, index);
}

function isDepthZero(path: string): boolean {
  return !path.includes("/");
}

function repoUrl(ctx: RepoScanContext): string {
  return `https://github.com/${ctx.repo.owner}/${ctx.repo.repo}`;
}

function blobUrl(ctx: RepoScanContext, path: string): string {
  const encoded = path
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  return `${repoUrl(ctx)}/blob/${ctx.repo.sha}/${encoded}`;
}

function fileText(ctx: RepoScanContext, path: string): string | undefined {
  return ctx.repo.files.find((file) => file.path === path)?.text;
}

function finding(
  ctx: RepoScanContext,
  checkId: string,
  input: {
    severity: RawFinding["severity"];
    confidence: RawFinding["confidence"];
    title: string;
    evidence: string;
    path?: string;
  },
): RawFinding {
  return {
    checkId,
    severity: input.severity,
    confidence: input.confidence,
    title: input.title,
    evidence: input.evidence,
    location: input.path === undefined ? repoUrl(ctx) : blobUrl(ctx, input.path),
  };
}

/**
 * repo.quality.basics — low-severity hygiene checks over the file tree plus
 * the already-fetched package.json and .gitignore contents: README, lockfile,
 * .gitignore (and whether it ignores env files), and tests.
 */
export const qualityBasicsCheck: RepoCheck = {
  id: "repo.quality.basics",
  category: "reliability",
  target: "repo",
  async run(ctx: RepoScanContext): Promise<RawFinding[]> {
    const { repo } = ctx;
    const paths = repo.tree.map((entry) => entry.path);
    const findings: RawFinding[] = [];
    const checkId = this.id;

    // README at the repository root.
    const hasReadme = paths.some(
      (path) => isDepthZero(path) && /^readme(\..+)?$/i.test(basename(path)),
    );
    if (!hasReadme) {
      findings.push(
        finding(ctx, checkId, {
          severity: "low",
          confidence: "high",
          title: "No README found at the repository root",
          evidence: "README not found",
        }),
      );
    }

    // Lockfile at the root or in any workspace root (a dir containing
    // package.json).
    const packageJsonDirs = new Set(
      paths
        .filter((path) => basename(path).toLowerCase() === "package.json")
        .map(dirName),
    );
    const hasLockfile = paths.some((path) => {
      if (!LOCKFILE_NAMES.has(basename(path).toLowerCase())) {
        return false;
      }
      const dir = dirName(path);
      return dir === "" || packageJsonDirs.has(dir);
    });
    if (!hasLockfile) {
      findings.push(
        finding(ctx, checkId, {
          severity: "low",
          confidence: "high",
          title: "No lockfile found",
          evidence: "lockfile not found at the root or in any workspace root",
        }),
      );
    }

    // .gitignore at the repository root.
    const gitignorePath = paths.find(
      (path) => isDepthZero(path) && basename(path).toLowerCase() === ".gitignore",
    );
    if (gitignorePath === undefined) {
      findings.push(
        finding(ctx, checkId, {
          severity: "low",
          confidence: "high",
          title: "No .gitignore found at the repository root",
          evidence: ".gitignore not found",
        }),
      );
    } else {
      // Only evaluate env coverage when the file was actually fetched.
      const gitignore = fileText(ctx, gitignorePath);
      if (gitignore !== undefined) {
        const ignoresEnv = gitignore
          .split("\n")
          .map((line) => line.trim())
          .some((line) => line !== "" && !line.startsWith("#") && line.includes(".env"));
        if (!ignoresEnv) {
          findings.push(
            finding(ctx, checkId, {
              severity: "medium",
              confidence: "medium",
              title: "The root .gitignore does not ignore environment files",
              evidence: "no .env or *.env pattern found in .gitignore",
              path: gitignorePath,
            }),
          );
        }
      }
    }

    // Tests: test/spec files, __tests__ or tests directories, or a test
    // script in any fetched package.json.
    const hasTestFile = paths.some((path) => {
      const segments = path.split("/");
      const base = basename(path);
      if (TEST_FILE_RE.test(base)) {
        return true;
      }
      return segments.slice(0, -1).some((segment) => segment === "__tests__" || segment === "tests");
    });
    const hasTestScript = repo.files.some(
      (file) =>
        basename(file.path).toLowerCase() === "package.json" && TEST_SCRIPT_RE.test(file.text),
    );
    if (!hasTestFile && !hasTestScript) {
      findings.push(
        finding(ctx, checkId, {
          severity: "low",
          confidence: "low",
          title: "No tests found",
          evidence: "no test files, test directories, or test script found",
        }),
      );
    }

    return findings;
  },
};
