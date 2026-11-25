import { envCommittedCheck } from "@/lib/scanner/checks/repo/env-committed";
import { qualityBasicsCheck } from "@/lib/scanner/checks/repo/quality-basics";
import { repoSecretsPatternsCheck } from "@/lib/scanner/checks/repo/secrets-patterns";
import type { RepoCheck } from "@/lib/scanner/types";

/** Repo checks enabled so far (Phase 3A). Add new checks here as phases land. */
export const repoChecks: RepoCheck[] = [
  envCommittedCheck,
  repoSecretsPatternsCheck,
  qualityBasicsCheck,
];
