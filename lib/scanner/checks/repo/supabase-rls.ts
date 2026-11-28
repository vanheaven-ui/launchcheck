import type { RawFinding, RepoCheck, RepoScanContext } from "@/lib/scanner/types";

/**
 * repo.supabase.rls — heuristic check over fetched .sql files: tables created
 * without a matching `enable row level security`, explicit `disable` statements,
 * and overly permissive policies (using/with check (true) on writes).
 */

const MAX_TABLES = 10;
const MAX_POLICIES = 10;

// SQL identifiers may be double-quoted, single-quoted, or backtick-quoted;
// a qualified name is `ident` or `schema.ident`. Each identifier contributes
// four capture groups (double-quoted, single-quoted, backtick-quoted, bare);
// a second identifier present means schema.name. A literal backtick cannot
// appear inside a String.raw template, so it is written as \x60.
const IDENT = String.raw`(?:"([^"]+)"|'([^']+)'|\x60([^\x60]+)\x60|(\w+))`;
const QUALIFIED = String.raw`${IDENT}(?:\s*\.\s*${IDENT})?`;

const CREATE_TABLE_RE = new RegExp(
  String.raw`\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?:temp(?:orary)?\s+)?` + QUALIFIED,
  "gi",
);
const TEMP_TABLE_RE = /\bcreate\s+temp(?:orary)?\s+table\b/i;
const ENABLE_RLS_RE = new RegExp(
  String.raw`\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?` +
    QUALIFIED +
    String.raw`\s+enable\s+row\s+level\s+security`,
  "gi",
);
const DISABLE_RLS_RE = new RegExp(
  String.raw`\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?` +
    QUALIFIED +
    String.raw`\s+disable\s+row\s+level\s+security`,
  "gi",
);
const POLICY_RE = new RegExp(
  String.raw`\bcreate\s+policy\s+["'\x60]?(\w+)["'\x60]?\s+on\s+` +
    QUALIFIED +
    String.raw`[\s\S]*?;`,
  "gi",
);
const POLICY_WRITE_RE = /\bfor\s+(insert|update|delete|all)\b/i;
const POLICY_TRUE_RE = /(?:using|with\s+check)\s*\(\s*true\s*\)/i;

/** Resolve the 8 identifier capture groups at `offset` into { schema?, name }. */
function qualifiedName(
  match: RegExpMatchArray,
  offset: number,
): { schema?: string; name?: string } {
  const first = match[offset] ?? match[offset + 1] ?? match[offset + 2] ?? match[offset + 3];
  const second = match[offset + 4] ?? match[offset + 5] ?? match[offset + 6] ?? match[offset + 7];
  if (second !== undefined) {
    return { schema: first, name: second };
  }
  return { name: first };
}

function normalizeTable(schema: string | undefined, name: string): string | null {
  if (schema && schema.toLowerCase() !== "public") {
    return null;
  }
  return name.toLowerCase();
}

function blobUrl(ctx: RepoScanContext, path: string): string {
  const { owner, repo, sha } = ctx.repo;
  const encoded = path
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  return `https://github.com/${owner}/${repo}/blob/${sha}/${encoded}`;
}

export const supabaseRlsCheck: RepoCheck = {
  id: "repo.supabase.rls",
  category: "security",
  target: "repo",
  timeoutMs: 10_000,
  async run(ctx: RepoScanContext): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    const sqlFiles = ctx.repo.files.filter((file) => /\.sql$/i.test(file.path));
    if (sqlFiles.length === 0) {
      return [];
    }

    const created = new Map<string, { name: string; path: string }>();
    const enabled = new Set<string>();
    const disabled: { name: string; path: string }[] = [];
    const permissive: { policy: string; table: string; path: string }[] = [];

    for (let i = 0; i < sqlFiles.length; i++) {
      const file = sqlFiles[i];
      if (i > 0) {
        await new Promise((resolve) => setImmediate(resolve));
      }
      const text = file.text;

      // Collect CREATE TABLE names (public schema only, not temporary).
      for (const match of text.matchAll(CREATE_TABLE_RE)) {
        const { schema, name } = qualifiedName(match, 1);
        if (!name || TEMP_TABLE_RE.test(match[0])) {
          continue;
        }
        const table = normalizeTable(schema, name);
        if (table && !created.has(table)) {
          created.set(table, { name, path: file.path });
        }
      }

      for (const match of text.matchAll(ENABLE_RLS_RE)) {
        const { schema, name } = qualifiedName(match, 1);
        const table = name ? normalizeTable(schema, name) : null;
        if (table) {
          enabled.add(table);
        }
      }

      for (const match of text.matchAll(DISABLE_RLS_RE)) {
        const { schema, name } = qualifiedName(match, 1);
        const table = name ? normalizeTable(schema, name) : null;
        if (table) {
          disabled.push({ name: table, path: file.path });
        }
      }

      for (const match of text.matchAll(POLICY_RE)) {
        const statement = match[0];
        if (!POLICY_WRITE_RE.test(statement) || !POLICY_TRUE_RE.test(statement)) {
          continue;
        }
        const policy = match[1];
        const { schema, name: tableName } = qualifiedName(match, 2);
        const table = tableName ? normalizeTable(schema, tableName) : "unknown";
        if (table === null) {
          continue;
        }
        permissive.push({ policy: policy ?? "unnamed", table, path: file.path });
      }
    }

    // Confidence drops when the tree was truncated or a .sql file in the tree
    // was never fetched (we may have missed an enable statement).
    const treeSqlPaths = new Set(
      ctx.repo.tree.filter((e) => /\.sql$/i.test(e.path)).map((e) => e.path),
    );
    const fetchedSqlPaths = new Set(sqlFiles.map((f) => f.path));
    const missingSql = [...treeSqlPaths].some((p) => !fetchedSqlPaths.has(p));
    const rlsConfidence = ctx.repo.treeTruncated || missingSql ? "medium" : "high";

    const unprotected = [...created.entries()].filter(([table]) => !enabled.has(table));
    if (unprotected.length > 0) {
      const shown = unprotected.slice(0, MAX_TABLES);
      const rest = unprotected.length - shown.length;
      findings.push({
        checkId: this.id,
        severity: "high",
        confidence: rlsConfidence,
        title: "Possible tables without row level security",
        evidence:
          `tables: ${shown.map(([, t]) => t.name).join(", ")}` +
          (rest > 0 ? ` (+${rest} more)` : "") +
          ` — files: ${[...new Set(shown.map(([, t]) => t.path))].join(", ")}`,
        location: blobUrl(ctx, unprotected[0][1].path),
      });
    }

    if (disabled.length > 0) {
      const shown = disabled.slice(0, MAX_TABLES);
      findings.push({
        checkId: this.id,
        severity: "high",
        confidence: rlsConfidence,
        title: "Row level security explicitly disabled",
        evidence: `disabled on: ${shown.map((d) => d.name).join(", ")}`,
        location: blobUrl(ctx, disabled[0].path),
      });
    }

    if (permissive.length > 0) {
      const shown = permissive.slice(0, MAX_POLICIES);
      const rest = permissive.length - shown.length;
      findings.push({
        checkId: this.id,
        severity: "medium",
        confidence: "medium",
        title: "Possible overly permissive row level security policy",
        evidence:
          `policies: ${shown.map((p) => `${p.policy} on ${p.table}`).join("; ")}` +
          (rest > 0 ? ` (+${rest} more)` : "") +
          ` — files: ${[...new Set(shown.map((p) => p.path))].join(", ")}`,
        location: blobUrl(ctx, permissive[0].path),
      });
    }

    return findings;
  },
};
