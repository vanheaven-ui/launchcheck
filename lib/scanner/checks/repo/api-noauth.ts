import type { RawFinding, RepoCheck, RepoScanContext } from "@/lib/scanner/types";

/**
 * repo.api.noauth — flags Next.js route handlers and server actions that touch
 * data (db/prisma/supabase) without any auth signal. Heuristic, low confidence.
 */

const MAX_FINDINGS = 10;
const ROUTE_PATH_RE = /(^|\/)app\/.+\/route\.(ts|tsx|js|jsx)$|(^|\/)pages\/api\//;
const USE_SERVER_RE = /^["']use server["']/m;
const SKIP_SEGMENT_RE =
  /(^|\/)(api\/auth|\[\.\.\.nextauth\]|health|healthz|sitemap|robots|og|opengraph)(\/|$|\.)/i;
const TEST_PATH_RE = /(^|[/._-])(tests?|spec|fixtures?|mocks?|samples?|docs?)([/._-]|$)/i;

const TOUCHES_DATA_RE =
  /\bdrizzle\b|\bprisma\b|createClient\s*\(|\.from\s*\(|\.rpc\s*\(|\bdb\s*\.\s*(?:select|insert|update|delete|query)|\bsql\s*`/;
const AUTH_SIGNAL_RE =
  /\bauth\s*\(|getServerSession|getSession|currentUser|requireAuth|withAuth|supabase\.auth\.getUser|jwt\.verify|verifyToken|headers\s*\.\s*get\([^)]*authorization/i;
const METHOD_RE =
  /export\s+(?:const|async\s+function|function)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g;
const MIDDLEWARE_AUTH_RE = /auth|session|clerk|jwt/i;

function isCandidate(path: string, text: string): boolean {
  return ROUTE_PATH_RE.test(path) || USE_SERVER_RE.test(text);
}

function isSkipped(path: string): boolean {
  const base = path.slice(path.lastIndexOf("/") + 1);
  if (/\.env\.example$/i.test(base)) {
    return false;
  }
  if (TEST_PATH_RE.test(path)) {
    return true;
  }
  const lower = path.toLowerCase();
  if (lower.includes("stripe") || lower.includes("webhook")) {
    return true;
  }
  return SKIP_SEGMENT_RE.test(path);
}

function exportedMethods(text: string): string[] {
  const methods = new Set<string>();
  for (const match of text.matchAll(METHOD_RE)) {
    if (match[1]) {
      methods.add(match[1]);
    }
  }
  return [...methods];
}

export const apiNoauthCheck: RepoCheck = {
  id: "repo.api.noauth",
  category: "security",
  target: "repo",
  timeoutMs: 10_000,
  async run(ctx: RepoScanContext): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    const files = ctx.repo.files;

    const middlewareEntry = ctx.repo.tree.find((entry) =>
      /(^|\/)middleware\.(ts|js)$/.test(entry.path),
    );
    const middlewareText = middlewareEntry
      ? files.find((file) => file.path === middlewareEntry.path)?.text
      : undefined;
    const middlewareMayProtect =
      middlewareText !== undefined && MIDDLEWARE_AUTH_RE.test(middlewareText);

    for (let i = 0; i < files.length && findings.length < MAX_FINDINGS; i++) {
      const file = files[i];
      if (i > 0) {
        await new Promise((resolve) => setImmediate(resolve));
      }
      if (isSkipped(file.path) || !isCandidate(file.path, file.text)) {
        continue;
      }
      if (!TOUCHES_DATA_RE.test(file.text) || AUTH_SIGNAL_RE.test(file.text)) {
        continue;
      }

      const methods = exportedMethods(file.text);
      const isServerAction = USE_SERVER_RE.test(file.text);
      const mutating =
        isServerAction || methods.some((m) => ["POST", "PUT", "PATCH", "DELETE"].includes(m));
      const what = isServerAction && methods.length === 0 ? "server action" : methods.join(", ");

      findings.push({
        checkId: this.id,
        severity: mutating ? "medium" : "low",
        confidence: "low",
        title: `Possible unauthenticated endpoint${middlewareMayProtect ? " (middleware may protect this route)" : ""}`,
        evidence: `${what || "endpoint"} in ${file.path}`,
        location: blobUrl(ctx, file.path),
      });
    }

    return findings;
  },
};

function blobUrl(ctx: RepoScanContext, path: string): string {
  const { owner, repo, sha } = ctx.repo;
  const encoded = path
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  return `https://github.com/${owner}/${repo}/blob/${sha}/${encoded}`;
}
