import {
  decodeJwtPayload,
  findJwts,
  findSecrets,
  type SecretMatch,
} from "@/lib/scanner/patterns/secrets";
import { redactSecret } from "@/lib/scanner/redact";
import { severityRank } from "@/lib/scanner/severity";
import type {
  Confidence,
  RawFinding,
  RepoCheck,
  RepoScanContext,
  Severity,
} from "@/lib/scanner/types";

const MAX_FINDINGS = 20;
/** Paths that look like tests, fixtures, mocks, samples, or docs. */
const TEST_PATH_RE = /(^|[/._-])(tests?|spec|fixtures?|mocks?|samples?|docs?)([/._-]|$)/i;
const EXAMPLE_ENV_RE = /\.env\.example$/i;

type SecretCandidate = {
  patternId: string;
  name: string;
  severity: Severity;
  confidence: Confidence;
  value: string;
  path: string;
  line: number;
};

function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

function lineNumber(text: string, index: number): number {
  let line = 1;
  const end = Math.min(index, text.length);
  for (let i = 0; i < end; i++) {
    if (text.charCodeAt(i) === 10) {
      line += 1;
    }
  }
  return line;
}

function blobUrl(ctx: RepoScanContext, path: string): string {
  const { owner, repo, sha } = ctx.repo;
  const encoded = path
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  return `https://github.com/${owner}/${repo}/blob/${sha}/${encoded}`;
}

function isTestLikePath(path: string): boolean {
  const base = path.slice(path.lastIndexOf("/") + 1);
  // .env.example files are never down-ranked: a real-looking key there is a leak.
  if (EXAMPLE_ENV_RE.test(base)) {
    return false;
  }
  return TEST_PATH_RE.test(path);
}

function matchFields(match: SecretMatch, path: string, text: string): SecretCandidate {
  return {
    patternId: match.patternId,
    name: match.name,
    severity: match.severity,
    confidence: match.confidence,
    value: match.value,
    path,
    line: lineNumber(text, match.index),
  };
}

function collectFileSecrets(file: { path: string; text: string }): SecretCandidate[] {
  const candidates: SecretCandidate[] = [];
  const seen = new Set<string>();

  const push = (candidate: SecretCandidate) => {
    const key = `${candidate.patternId}${candidate.value}`;
    if (!seen.has(key)) {
      seen.add(key);
      candidates.push(candidate);
    }
  };

  for (const match of findSecrets(file.text)) {
    push(matchFields(match, file.path, file.text));
  }

  for (const jwt of findJwts(file.text)) {
    const payload = decodeJwtPayload(jwt.value);
    if (payload?.role === "service_role") {
      push({
        patternId: "supabase-service-role-jwt",
        name: "Supabase service_role JWT",
        severity: "critical",
        confidence: "high",
        value: jwt.value,
        path: file.path,
        line: lineNumber(file.text, jwt.index),
      });
    }
  }

  return candidates;
}

/**
 * repo.secrets.patterns — regex scan of every fetched text file for leaked
 * credentials, plus Supabase service_role JWTs. Matches in test-like paths
 * are down-ranked to low/low so a repo's own fake keys do not look like leaks.
 */
export const repoSecretsPatternsCheck: RepoCheck = {
  id: "repo.secrets.patterns",
  category: "secrets",
  target: "repo",
  timeoutMs: 15_000,
  async run(ctx: RepoScanContext): Promise<RawFinding[]> {
    const { repo } = ctx;
    const candidates: SecretCandidate[] = [];
    const seen = new Set<string>();

    for (let i = 0; i < repo.files.length; i++) {
      const file = repo.files[i];
      if (i > 0) {
        // Yield between files so a large repo cannot starve the event loop.
        await yieldToEventLoop();
      }
      for (const candidate of collectFileSecrets(file)) {
        const key = `${candidate.patternId}${candidate.value}`;
        if (seen.has(key)) {
          continue;
        }
        seen.add(key);
        candidates.push(candidate);
      }
    }

    // Worst findings first so the cap never hides a critical behind test noise.
    candidates.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

    return candidates.slice(0, MAX_FINDINGS).map((candidate) => {
      const downgraded = isTestLikePath(candidate.path);
      const severity: Severity = downgraded ? "low" : candidate.severity;
      const confidence: Confidence = downgraded ? "low" : candidate.confidence;

      return {
        checkId: this.id,
        severity,
        confidence,
        title:
          confidence === "high"
            ? `${candidate.name} found in repository`
            : `Possible ${candidate.name} found in repository`,
        evidence: `${candidate.name}: ${redactSecret(candidate.value)} at ${candidate.path}:${candidate.line}`,
        location: blobUrl(ctx, candidate.path),
      };
    });
  },
};
