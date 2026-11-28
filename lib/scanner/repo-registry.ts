import { apiNoauthCheck } from "@/lib/scanner/checks/repo/api-noauth";
import { depsAuditCheck } from "@/lib/scanner/checks/repo/deps-audit";
import { envCommittedCheck } from "@/lib/scanner/checks/repo/env-committed";
import { qualityBasicsCheck } from "@/lib/scanner/checks/repo/quality-basics";
import { repoSecretsPatternsCheck } from "@/lib/scanner/checks/repo/secrets-patterns";
import { stripeWebhookCheck } from "@/lib/scanner/checks/repo/stripe-webhook";
import { supabaseRlsCheck } from "@/lib/scanner/checks/repo/supabase-rls";
import type { RepoCheck } from "@/lib/scanner/types";

/** Repo checks enabled so far (Phase 3A/3B). Add new checks here as phases land. */
export const repoChecks: RepoCheck[] = [
  envCommittedCheck,
  repoSecretsPatternsCheck,
  qualityBasicsCheck,
  depsAuditCheck,
  stripeWebhookCheck,
  apiNoauthCheck,
  supabaseRlsCheck,
];
