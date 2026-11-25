import { describe, expect, it } from "vitest";
import { runRepoScan, unreadableRepoFinding } from "@/lib/scanner/scan-repo";
import { cleanRepoFiles } from "../../fixtures/repos/clean-repo";
import { VULN_REPO_STRIPE_KEY, vulnerableRepoFiles } from "../../fixtures/repos/vulnerable-repo";
import { createFakeGithub } from "../helpers/fake-github";

const VULN_URL = "https://github.com/acme/vulnerable-app";
const CLEAN_URL = "https://github.com/acme/clean-app";

describe("runRepoScan", () => {
  it("returns the failure reason when the repo cannot be read", async () => {
    const { github, fetcher } = createFakeGithub({});
    const result = await runRepoScan({ repoUrl: VULN_URL, github, fetcher });
    expect(result).toEqual({ ok: false, reason: "repo_not_found" });
  });

  it("returns repo_unreachable for an invalid repo URL", async () => {
    const { github, fetcher } = createFakeGithub({});
    const result = await runRepoScan({
      repoUrl: "https://example.com/not-a-repo",
      github,
      fetcher,
    });
    expect(result).toEqual({ ok: false, reason: "repo_unreachable" });
  });

  it("produces critical findings for the vulnerable fixture repo", async () => {
    const { github, fetcher } = createFakeGithub({
      "acme/vulnerable-app": {
        files: vulnerableRepoFiles,
        headSha: "1".repeat(40),
        treeSha: "2".repeat(40),
      },
    });
    const result = await runRepoScan({ repoUrl: VULN_URL, github, fetcher });
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // File-level findings (env.committed, secrets.patterns) link to
    // blob/<commit-sha>/<path>; repo-level findings (quality.basics without a
    // path) legitimately use the plain repository URL with no sha.
    const fileLevel = result.findings.filter(
      (f) => f.checkId === "repo.env.committed" || f.checkId === "repo.secrets.patterns",
    );
    expect(fileLevel.length).toBeGreaterThan(0);
    for (const finding of fileLevel) {
      expect(finding.location).toContain(`/blob/${"1".repeat(40)}/`);
    }
    // The tree sha must never appear in any location.
    for (const finding of result.findings) {
      expect(finding.location ?? "").not.toContain("2".repeat(40));
    }

    const envCommitted = result.findings.find((f) => f.checkId === "repo.env.committed");
    expect(envCommitted).toMatchObject({
      severity: "critical",
      confidence: "high",
      category: "secrets",
    });
    expect(envCommitted?.evidence).toContain(".env");
    expect(envCommitted?.evidence).not.toContain(VULN_REPO_STRIPE_KEY);

    const secrets = result.findings.filter((f) => f.checkId === "repo.secrets.patterns");
    expect(secrets.some((f) => f.severity === "critical" && f.title.includes("Stripe"))).toBe(true);
    expect(
      secrets.some(
        (f) => f.severity === "critical" && f.title.includes("Supabase service_role JWT"),
      ),
    ).toBe(true);
    // No finding may contain a full secret value.
    const serialized = JSON.stringify(result.findings);
    expect(serialized).not.toContain(VULN_REPO_STRIPE_KEY);

    const quality = result.findings.filter((f) => f.checkId === "repo.quality.basics");
    expect(quality.length).toBeGreaterThan(0);
    expect(quality.every((f) => f.severity === "low" || f.severity === "medium")).toBe(true);
  });

  it("produces no findings for the clean fixture repo", async () => {
    const { github, fetcher } = createFakeGithub({
      "acme/clean-app": { files: cleanRepoFiles },
    });
    const result = await runRepoScan({ repoUrl: CLEAN_URL, github, fetcher });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const nonInfo = result.findings.filter((f) => f.severity !== "info");
    expect(nonInfo).toEqual([]);
    for (const id of ["repo.env.committed", "repo.secrets.patterns", "repo.quality.basics"]) {
      expect(result.findings.some((f) => f.checkId === id)).toBe(false);
    }
  });

  it("converts snapshot notes into repo.snapshot.notes info findings", async () => {
    const { github, fetcher } = createFakeGithub({
      "acme/app": {
        files: { "a.ts": "x", "gone.ts": "y" },
        unfetchable: ["gone.ts"],
      },
    });
    const result = await runRepoScan({
      repoUrl: "https://github.com/acme/app",
      github,
      fetcher,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const note = result.findings.find((f) => f.checkId === "repo.snapshot.notes");
    expect(note).toMatchObject({ severity: "info", category: "reliability" });
  });

  it("runs only the provided checks when given", async () => {
    const { github, fetcher } = createFakeGithub({
      "acme/app": { files: { "a.ts": "x" } },
    });
    const result = await runRepoScan({
      repoUrl: "https://github.com/acme/app",
      github,
      fetcher,
      checks: [],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.findings.filter((f) => f.severity !== "info")).toEqual([]);
  });
});

describe("unreadableRepoFinding", () => {
  it("builds the single info finding for both-mode scans", () => {
    const finding = unreadableRepoFinding("repo_rate_limited");
    expect(finding).toMatchObject({
      checkId: "repo.snapshot.notes",
      category: "reliability",
      severity: "info",
      confidence: "high",
      title: "The repository could not be scanned",
      evidence: "repo_rate_limited",
    });
  });
});
