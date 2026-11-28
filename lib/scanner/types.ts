import type { IncomingHttpHeaders } from "node:http";
import type { OsvClient } from "@/lib/scanner/osv";
import type { SafeFetchResult } from "@/lib/scanner/safe-fetch";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";
export type Category = "security" | "secrets" | "performance" | "reliability";

/** A raw finding. `evidence` must already be redacted before it gets here. */
export type RawFinding = {
  checkId: string;
  severity: Severity;
  title: string;
  evidence: string;
  location?: string;
  confidence: Confidence;
};

/** A finding with its check's category attached (runner output). */
export type ScanFinding = RawFinding & { category: Category };

/** Injected fetcher: production uses safeFetch; tests use fixture servers. */
export type Fetcher = (url: string) => Promise<SafeFetchResult>;

export type SiteScript = {
  url: string;
  body: string;
  truncated: boolean;
};

export type SiteSnapshot = {
  requestedUrl: string;
  finalUrl: string;
  status: number;
  headers: IncomingHttpHeaders;
  html: string;
  htmlTruncated: boolean;
  /** Wall-clock time of the home page fetch, in milliseconds. */
  fetchMs: number;
  scripts: SiteScript[];
  /** Human-readable notes about skipped fetches and budget exhaustion. */
  notes: string[];
};

export type RepoTreeEntry = {
  path: string;
  size: number | null;
};

export type RepoFile = {
  path: string;
  text: string;
  truncated: boolean;
};

/** Everything repo checks need: the file tree plus fetched text contents. */
export type RepoSnapshot = {
  owner: string;
  repo: string;
  defaultBranch: string;
  /** Commit SHA the tree and file contents were read at. */
  sha: string;
  /** True when GitHub truncated the recursive tree listing. */
  treeTruncated: boolean;
  /** Every blob in the tree (including files skipped for content scanning). */
  tree: RepoTreeEntry[];
  files: RepoFile[];
  /** Human-readable notes about skipped files and budget exhaustion. */
  notes: string[];
};

export type ScanContext = {
  snapshot: SiteSnapshot;
  fetch: Fetcher;
};

export type RepoScanContext = {
  repo: RepoSnapshot;
  /** Injected fetcher for extra repo files (e.g. lockfiles) via safeFetch. */
  fetch: Fetcher;
  /** Injected OSV client for the dependency audit. */
  osv: OsvClient;
  /** Injectable clock for checks with internal budgets. */
  now?: () => number;
};

export type Check = {
  id: string;
  category: Category;
  target: "site";
  /** Per-check timeout override; the runner default applies when absent. */
  timeoutMs?: number;
  run(ctx: ScanContext): Promise<RawFinding[]>;
};

export type RepoCheck = {
  id: string;
  category: Category;
  target: "repo";
  /** Per-check timeout override; the runner default applies when absent. */
  timeoutMs?: number;
  run(ctx: RepoScanContext): Promise<RawFinding[]>;
};
