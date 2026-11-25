import { describe, expect, it } from "vitest";
import { qualityBasicsCheck } from "@/lib/scanner/checks/repo/quality-basics";
import { makeRepoContext } from "../../helpers/repo";

function treePaths(...paths: string[]) {
  return paths.map((path) => ({ path, size: 10 }));
}

function file(path: string, text: string) {
  return { path, text, truncated: false };
}

/** A repo that passes every quality rule. */
function cleanCtx() {
  return makeRepoContext({
    tree: treePaths(
      "README.md",
      "package.json",
      "pnpm-lock.yaml",
      ".gitignore",
      "src/index.ts",
      "src/index.test.ts",
    ),
    files: [
      file("package.json", JSON.stringify({ scripts: { test: "vitest" } })),
      file(".gitignore", "node_modules/\n.env\n*.env\n"),
    ],
  });
}

describe("repo.quality.basics", () => {
  it("returns nothing for a clean repo", async () => {
    expect(await qualityBasicsCheck.run(cleanCtx())).toEqual([]);
  });

  it("flags a missing README", async () => {
    const ctx = makeRepoContext({
      tree: treePaths("package.json", "pnpm-lock.yaml", ".gitignore", "a.test.ts"),
      files: [file("package.json", "{}"), file(".gitignore", ".env\n")],
    });
    const findings = await qualityBasicsCheck.run(ctx);
    const readme = findings.find((f) => f.title.includes("README"));
    expect(readme).toMatchObject({ severity: "low", confidence: "high" });
    expect(readme?.evidence).toBe("README not found");
    expect(readme?.location).toBe("https://github.com/acme/app");
  });

  it("accepts README at any casing and with an extension", async () => {
    for (const name of ["README", "readme.md", "ReadMe.txt"]) {
      const ctx = makeRepoContext({
        tree: treePaths(name, "package.json", "pnpm-lock.yaml", ".gitignore", "a.test.ts"),
        files: [file(".gitignore", ".env\n")],
      });
      const findings = await qualityBasicsCheck.run(ctx);
      expect(
        findings.some((f) => f.title.includes("README")),
        name,
      ).toBe(false);
    }
  });

  it("flags a missing lockfile", async () => {
    const ctx = makeRepoContext({
      tree: treePaths("README.md", "package.json", ".gitignore", "a.test.ts"),
      files: [file(".gitignore", ".env\n")],
    });
    const findings = await qualityBasicsCheck.run(ctx);
    expect(findings.some((f) => f.title === "No lockfile found")).toBe(true);
  });

  it("accepts a lockfile in a workspace root", async () => {
    const ctx = makeRepoContext({
      tree: treePaths(
        "README.md",
        "package.json",
        "packages/a/package.json",
        "packages/a/pnpm-lock.yaml",
        ".gitignore",
        "a.test.ts",
      ),
      files: [file(".gitignore", ".env\n")],
    });
    const findings = await qualityBasicsCheck.run(ctx);
    expect(findings.some((f) => f.title === "No lockfile found")).toBe(false);
  });

  it("flags a missing .gitignore", async () => {
    const ctx = makeRepoContext({
      tree: treePaths("README.md", "package.json", "pnpm-lock.yaml", "a.test.ts"),
      files: [file("package.json", "{}")],
    });
    const findings = await qualityBasicsCheck.run(ctx);
    const gitignore = findings.find((f) => f.title.includes(".gitignore"));
    expect(gitignore).toMatchObject({ severity: "low", confidence: "high" });
    expect(gitignore?.evidence).toBe(".gitignore not found");
  });

  it("flags a .gitignore that does not ignore env files (medium/medium)", async () => {
    const ctx = makeRepoContext({
      tree: treePaths("README.md", "package.json", "pnpm-lock.yaml", ".gitignore", "a.test.ts"),
      files: [file(".gitignore", "node_modules/\ndist/\n")],
    });
    const findings = await qualityBasicsCheck.run(ctx);
    const env = findings.find((f) => f.title.includes("environment files"));
    expect(env).toMatchObject({ severity: "medium", confidence: "medium" });
    expect(env?.location).toContain("/blob/");
    expect(env?.location).toContain(".gitignore");
  });

  it("accepts .gitignore env patterns like .env, *.env, and .env.*", async () => {
    for (const pattern of [".env", "*.env", ".env.*", "**/.env"]) {
      const ctx = makeRepoContext({
        tree: treePaths("README.md", "package.json", "pnpm-lock.yaml", ".gitignore", "a.test.ts"),
        files: [file(".gitignore", `node_modules/\n${pattern}\n`)],
      });
      const findings = await qualityBasicsCheck.run(ctx);
      expect(
        findings.some((f) => f.title.includes("environment files")),
        pattern,
      ).toBe(false);
    }
  });

  it("flags missing tests at low/low", async () => {
    const ctx = makeRepoContext({
      tree: treePaths("README.md", "package.json", "pnpm-lock.yaml", ".gitignore", "src/index.ts"),
      files: [file(".gitignore", ".env\n")],
    });
    const findings = await qualityBasicsCheck.run(ctx);
    const tests = findings.find((f) => f.title === "No tests found");
    expect(tests).toMatchObject({ severity: "low", confidence: "low" });
  });

  it("accepts tests via *.test.*, *.spec.*, __tests__, tests/, or a test script", async () => {
    const variants = [
      treePaths("README.md", "pnpm-lock.yaml", ".gitignore", "src/a.test.ts"),
      treePaths("README.md", "pnpm-lock.yaml", ".gitignore", "src/a.spec.tsx"),
      treePaths("README.md", "pnpm-lock.yaml", ".gitignore", "src/__tests__/a.ts"),
      treePaths("README.md", "pnpm-lock.yaml", ".gitignore", "tests/a.ts"),
      treePaths("README.md", "pnpm-lock.yaml", ".gitignore", "package.json", "src/a.ts"),
    ];
    for (const [i, tree] of variants.entries()) {
      const files = [file(".gitignore", ".env\n")];
      if (i === 4) {
        files.push(file("package.json", JSON.stringify({ scripts: { test: "vitest" } })));
      }
      const ctx = makeRepoContext({ tree, files });
      const findings = await qualityBasicsCheck.run(ctx);
      expect(
        findings.some((f) => f.title === "No tests found"),
        `variant ${i}`,
      ).toBe(false);
    }
  });

  it("does not count a 'test' key outside scripts as a test script", async () => {
    const ctx = makeRepoContext({
      tree: treePaths("README.md", "pnpm-lock.yaml", ".gitignore", "package.json"),
      files: [
        file(".gitignore", ".env\n"),
        file("package.json", JSON.stringify({ test: "not-a-script", scripts: { dev: "x" } })),
      ],
    });
    const findings = await qualityBasicsCheck.run(ctx);
    expect(findings.some((f) => f.title === "No tests found")).toBe(true);
  });
});
