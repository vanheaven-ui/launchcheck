import { describe, expect, it } from "vitest";
import { envCommittedCheck } from "@/lib/scanner/checks/repo/env-committed";
import { makeRepoContext, makeRepoSnapshot } from "../../helpers/repo";

function treePaths(...paths: string[]) {
  return paths.map((path) => ({ path, size: 10 }));
}

describe("repo.env.committed", () => {
  it("returns nothing when no env files exist", async () => {
    const ctx = makeRepoContext({ tree: treePaths("src/index.ts", "README.md") });
    expect(await envCommittedCheck.run(ctx)).toEqual([]);
  });

  it("excludes .example/.sample/.template/.defaults/.dist variants", async () => {
    const ctx = makeRepoContext({
      tree: treePaths(
        ".env.example",
        ".env.sample",
        ".env.template",
        ".env.defaults",
        ".env.dist",
        "config/.env.production.example",
      ),
    });
    expect(await envCommittedCheck.run(ctx)).toEqual([]);
  });

  it("flags .env variants at any depth", async () => {
    const ctx = makeRepoContext({
      tree: treePaths(".env", "config/.env.local", "prod.env", "src/.env.production"),
    });
    const findings = await envCommittedCheck.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      checkId: "repo.env.committed",
      severity: "high",
      confidence: "medium",
      title: "An environment file is committed to the repository",
    });
    expect(findings[0].evidence).toContain(".env");
    expect(findings[0].evidence).toContain("prod.env");
    expect(findings[0].location).toBe(
      `https://github.com/acme/app/blob/${makeRepoSnapshot().sha}/.env`,
    );
  });

  it("is critical/high when a fetched env file has a KEY=value line", async () => {
    const ctx = makeRepoContext({
      tree: treePaths(".env"),
      files: [{ path: ".env", text: "API_KEY=abc123\nOTHER=\n", truncated: false }],
    });
    const findings = await envCommittedCheck.run(ctx);
    expect(findings[0]).toMatchObject({ severity: "critical", confidence: "high" });
  });

  it("stays high severity when the env file has only empty values", async () => {
    const ctx = makeRepoContext({
      tree: treePaths(".env"),
      files: [{ path: ".env", text: 'API_KEY=\nEMPTY=""\n', truncated: false }],
    });
    const findings = await envCommittedCheck.run(ctx);
    expect(findings[0]).toMatchObject({ severity: "high" });
  });

  it("lists at most 5 paths and never includes file contents", async () => {
    const paths = Array.from({ length: 8 }, (_, i) => `.env.${i}`);
    const secretish = "sk" + "_live_" + "q".repeat(24);
    const ctx = makeRepoContext({
      tree: treePaths(...paths),
      files: [{ path: ".env.0", text: `KEY=${secretish}\n`, truncated: false }],
    });
    const findings = await envCommittedCheck.run(ctx);
    const evidence = findings[0].evidence;
    expect(evidence).toContain("(+3 more)");
    expect(evidence).not.toContain(secretish);
    expect(evidence).not.toContain("KEY=");
    expect((evidence.match(/\.env\./g) ?? []).length).toBeLessThanOrEqual(5);
  });
});
