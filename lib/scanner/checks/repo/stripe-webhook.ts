import type { RawFinding, RepoCheck, RepoScanContext } from "@/lib/scanner/types";

/**
 * repo.stripe.webhook — flags files that look like Stripe webhook handlers but
 * never call constructEvent/constructEventAsync, so signature verification may
 * be missing. Heuristic only: every finding is a "possible" issue.
 */

const MAX_FINDINGS = 5;
const STRIPE_EVENT_RE =
  /checkout\.session\.completed|payment_intent\.succeeded|invoice\.paid|customer\.subscription\.(?:created|updated|deleted)/;
const SIGNATURE_HEADER_RE = /stripe-signature/i;
const CONSTRUCT_EVENT_RE = /constructEvent(?:Async)?\s*\(/;
const LOCAL_PROVIDER_RE = /(?:from|import)\s*\(?\s*["'][^"']*(?:stripe|webhook)[^"']*["']/i;
const TEST_PATH_RE = /(^|[/._-])(tests?|spec|fixtures?|mocks?|samples?|docs?)([/._-]|$)/i;

function isTestLikePath(path: string): boolean {
  const base = path.slice(path.lastIndexOf("/") + 1);
  if (/\.env\.example$/i.test(base)) {
    return false;
  }
  return TEST_PATH_RE.test(path);
}

function blobUrl(ctx: RepoScanContext, path: string): string {
  const { owner, repo, sha } = ctx.repo;
  const encoded = path
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  return `https://github.com/${owner}/${repo}/blob/${sha}/${encoded}`;
}

function looksLikeWebhookHandler(path: string, text: string): boolean {
  const lower = path.toLowerCase();
  if (lower.includes("webhook") && lower.includes("stripe")) {
    return true;
  }
  return SIGNATURE_HEADER_RE.test(text) || STRIPE_EVENT_RE.test(text);
}

export const stripeWebhookCheck: RepoCheck = {
  id: "repo.stripe.webhook",
  category: "security",
  target: "repo",
  timeoutMs: 10_000,
  async run(ctx: RepoScanContext): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    const files = ctx.repo.files;

    for (let i = 0; i < files.length && findings.length < MAX_FINDINGS; i++) {
      const file = files[i];
      if (i > 0) {
        await new Promise((resolve) => setImmediate(resolve));
      }
      if (!looksLikeWebhookHandler(file.path, file.text)) {
        continue;
      }
      if (CONSTRUCT_EVENT_RE.test(file.text)) {
        continue;
      }

      const testLike = isTestLikePath(file.path);
      // A relative import mentioning stripe/webhook may hold the verification.
      const delegates = LOCAL_PROVIDER_RE.test(file.text);
      const severity = testLike ? "low" : "high";
      const confidence = testLike || delegates ? "low" : "medium";

      findings.push({
        checkId: this.id,
        severity,
        confidence,
        title: "Possible Stripe webhook without signature verification",
        evidence: `no constructEvent call found in this file (${file.path})`,
        location: blobUrl(ctx, file.path),
      });
    }

    return findings;
  },
};
