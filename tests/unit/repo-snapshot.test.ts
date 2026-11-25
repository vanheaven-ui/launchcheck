import { describe, expect, it } from "vitest";
import { GithubError } from "@/lib/scanner/github";
import { buildRepoSnapshot, parseRepoUrl } from "@/lib/scanner/repo-snapshot";
import type { Fetcher } from "@/lib/scanner/types";
import { createFakeGithub } from "../helpers/fake-github";
import { okResult } from "../helpers/fetcher";

const REPO_URL = "https://github.com/acme/app";

describe("parseRepoUrl", () => {
  it("parses a plain repo URL", () => {
    expect(parseRepoUrl("https://github.com/acme/app")).toEqual({ owner: "acme", repo: "app" });
  });

  it("accepts a .git suffix and a trailing slash", () => {
    expect(parseRepoUrl("https://github.com/acme/app.git/")).toEqual({
      owner: "acme",
      repo: "app",
    });
  });

  it("rejects non-GitHub hosts, extra segments, queries, and credentials", () => {
    for (const url of [
      "https://gitlab.com/acme/app",
      "https://github.com/acme/app/issues",
      "https://github.com/acme/app?tab=readme",
      "https://user:pass@github.com/acme/app",
      "http://github.com/acme/app",
      "not a url",
      "https://github.com/acme",
    ]) {
      expect(parseRepoUrl(url)).toBeNull();
    }
  });
});

describe("buildRepoSnapshot", () => {
  it("fetches files in priority order: env/config, then app dirs, then the rest", async () => {
    const { github, fetcher } = createFakeGithub({
      "acme/app": {
        files: {
          "z-last.txt": "z",
          "src/b.ts": "b",
          "app/page.tsx": "p",
          ".env": "A=1",
          "config/app.json": "{}",
          "README.md": "hi",
        },
      },
    });
    const result = await buildRepoSnapshot(REPO_URL, { github, fetcher });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const paths = result.snapshot.files.map((f) => f.path);
    // Tier 0 (env/config files): .env and config/app.json come first, shallow first.
    expect(paths[0]).toBe(".env");
    expect(paths[1]).toBe("config/app.json");
    // Tier 1 (app/, src/, ...): both depth 2, alphabetical -> app before src.
    expect(paths.indexOf("app/page.tsx")).toBeLessThan(paths.indexOf("src/b.ts"));
    // Tier 2 (everything else): README.md and z-last.txt, shallow/alpha order.
    expect(paths.indexOf("src/b.ts")).toBeLessThan(paths.indexOf("README.md"));
    expect(paths.indexOf("README.md")).toBeLessThan(paths.indexOf("z-last.txt"));
  });

  it("skips node_modules, lockfiles, minified files, maps, and binaries", async () => {
    const { github, fetcher, fetchedUrls } = createFakeGithub({
      "acme/app": {
        files: {
          "src/index.ts": "ok",
          "node_modules/pkg/index.js": "bad",
          "dist/bundle.js": "bad",
          "pnpm-lock.yaml": "lock",
          "app.min.js": "min",
          "styles.css.map": "map",
          "logo.png": "png",
        },
      },
    });
    const result = await buildRepoSnapshot(REPO_URL, { github, fetcher });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.snapshot.files.map((f) => f.path)).toEqual(["src/index.ts"]);
    // Skipped paths still appear in the tree listing.
    const treePaths = result.snapshot.tree.map((t) => t.path);
    expect(treePaths).toContain("node_modules/pkg/index.js");
    expect(treePaths).toContain("pnpm-lock.yaml");
    for (const url of fetchedUrls) {
      expect(url).toContain("raw.githubusercontent.com");
      expect(url).not.toContain("node_modules");
    }
  });

  it("skips files whose tree size exceeds 200 KB and notes it", async () => {
    const { github, fetcher, fetchedUrls } = createFakeGithub({
      "acme/app": {
        files: {
          "big.bin.ts": "x".repeat(10),
          "small.ts": "ok",
        },
        sizes: { "big.bin.ts": 300 * 1024 },
      },
    });
    const result = await buildRepoSnapshot(REPO_URL, { github, fetcher });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.snapshot.files.map((f) => f.path)).toEqual(["small.ts"]);
    expect(fetchedUrls.some((u) => u.includes("big.bin.ts"))).toBe(false);
    expect(result.snapshot.notes.some((n) => n.includes("larger than 200 KB"))).toBe(true);
  });

  it("truncates fetched bodies to 200 KB", async () => {
    const big = "x".repeat(300 * 1024);
    const { github, fetcher } = createFakeGithub({
      "acme/app": {
        files: { "big.ts": big },
        // Tree size under the cap so the file is fetched; the body itself is larger.
        sizes: { "big.ts": 1024 },
      },
    });
    const result = await buildRepoSnapshot(REPO_URL, { github, fetcher });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const file = result.snapshot.files[0];
    expect(file.truncated).toBe(true);
    expect(Buffer.byteLength(file.text, "utf8")).toBe(200 * 1024);
  });

  it("caps fetched files at 300 and notes the overflow", async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 305; i++) {
      files[`src/f${String(i).padStart(3, "0")}.ts`] = "x";
    }
    const { github, fetcher } = createFakeGithub({ "acme/app": { files } });
    const result = await buildRepoSnapshot(REPO_URL, { github, fetcher });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.snapshot.files).toHaveLength(300);
    expect(result.snapshot.notes.some((n) => n.includes("300-file limit"))).toBe(true);
  });

  it("enforces the 15 MB total budget and notes leftovers", async () => {
    const files: Record<string, string> = {};
    // ~204.8 KB each (just under the per-file cap): the 15 MB budget is hit
    // after ~77 files; concurrency overshoot is bounded by 6, so 120 files
    // guarantees leftovers were skipped.
    for (let i = 0; i < 120; i++) {
      files[`src/f${String(i).padStart(3, "0")}.ts`] = "x".repeat(200 * 1024 - 1);
    }
    const { github, fetcher } = createFakeGithub({ "acme/app": { files } });
    const result = await buildRepoSnapshot(REPO_URL, { github, fetcher });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.snapshot.files.length).toBeLessThan(120);
    expect(result.snapshot.notes.some((n) => n.includes("15 MB"))).toBe(true);
  }, 30_000);

  it("stops at the deadline and notes skipped files", async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 10; i++) {
      files[`src/f${i}.ts`] = "x";
    }
    const { github, fetcher } = createFakeGithub({ "acme/app": { files } });
    // Each now() call jumps 20s forward, so the 25s deadline hits quickly.
    let tick = 0;
    const now = () => {
      tick += 20_000;
      return tick;
    };
    const result = await buildRepoSnapshot(REPO_URL, {
      github,
      fetcher,
      now,
      deadlineMs: 25_000,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.snapshot.files.length).toBeLessThan(10);
    expect(result.snapshot.notes.some((n) => n.includes("scan budget"))).toBe(true);
  });

  it("encodes every path segment in the raw URL", async () => {
    const { github, fetcher, fetchedUrls } = createFakeGithub({
      "acme/app": { files: { "src/my file#1.ts": "x" } },
    });
    const result = await buildRepoSnapshot(REPO_URL, { github, fetcher });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(fetchedUrls).toHaveLength(1);
    expect(fetchedUrls[0]).toContain("my%20file%231.ts");
    expect(result.snapshot.files[0].path).toBe("src/my file#1.ts");
  });

  it("records fetch failures as notes and never throws", async () => {
    const { github, fetcher } = createFakeGithub({
      "acme/app": {
        files: { "good.ts": "ok", "bad.ts": "x" },
        unfetchable: ["bad.ts"],
      },
    });
    const result = await buildRepoSnapshot(REPO_URL, { github, fetcher });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.snapshot.files.map((f) => f.path)).toEqual(["good.ts"]);
    expect(result.snapshot.notes.some((n) => n.includes("could not be fetched"))).toBe(true);
  });

  it("notes a truncated tree", async () => {
    const { github, fetcher } = createFakeGithub({
      "acme/app": { files: { "a.ts": "x" }, treeTruncated: true },
    });
    const result = await buildRepoSnapshot(REPO_URL, { github, fetcher });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.snapshot.treeTruncated).toBe(true);
    expect(result.snapshot.notes.some((n) => n.toLowerCase().includes("truncated"))).toBe(true);
  });

  it("returns repo_not_found for an unknown repo", async () => {
    const { github, fetcher } = createFakeGithub({});
    const result = await buildRepoSnapshot("https://github.com/acme/missing", {
      github,
      fetcher,
    });
    expect(result).toEqual({ ok: false, reason: "repo_not_found" });
  });

  it("returns repo_unreachable for an invalid repo URL", async () => {
    const { github, fetcher } = createFakeGithub({});
    const result = await buildRepoSnapshot("https://gitlab.com/acme/app", { github, fetcher });
    expect(result).toEqual({ ok: false, reason: "repo_unreachable" });
  });

  it("returns repo_unreachable when github throws a non-GithubError", async () => {
    const { github, fetcher } = createFakeGithub({ "acme/app": { files: {} } });
    const failing = {
      ...github,
      getRepo: async () => {
        throw new Error("boom");
      },
    };
    const result = await buildRepoSnapshot(REPO_URL, { github: failing, fetcher });
    expect(result).toEqual({ ok: false, reason: "repo_unreachable" });
  });

  it("maps GithubError codes through unchanged", async () => {
    const { github, fetcher } = createFakeGithub({ "acme/app": { files: {} } });
    const limited = {
      ...github,
      getRepo: async () => {
        throw new GithubError("repo_rate_limited", "The GitHub rate limit was reached.");
      },
    };
    const result = await buildRepoSnapshot(REPO_URL, { github: limited, fetcher });
    expect(result).toEqual({ ok: false, reason: "repo_rate_limited" });
  });

  it("never throws even when the fetcher throws", async () => {
    const { github } = createFakeGithub({
      "acme/app": { files: { "a.ts": "x", "b.ts": "y" } },
    });
    const throwingFetcher: Fetcher = async () => {
      throw new Error("network exploded");
    };
    const result = await buildRepoSnapshot(REPO_URL, { github, fetcher: throwingFetcher });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.snapshot.files).toEqual([]);
    expect(result.snapshot.notes.some((n) => n.includes("could not be fetched"))).toBe(true);
  });

  it("serves file contents through the injected fetcher only", async () => {
    const { github } = createFakeGithub({ "acme/app": { files: { "a.ts": "content-a" } } });
    const seen: string[] = [];
    const fetcher: Fetcher = async (url) => {
      seen.push(url);
      return okResult(url, "served-by-test");
    };
    const result = await buildRepoSnapshot(REPO_URL, { github, fetcher });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(seen).toHaveLength(1);
    expect(result.snapshot.files[0].text).toBe("served-by-test");
  });
});
