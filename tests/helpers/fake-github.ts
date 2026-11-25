import { type GithubClient, GithubError } from "@/lib/scanner/github";
import type { Fetcher } from "@/lib/scanner/types";
import { okResult } from "./fetcher";

export type FakeRepoSpec = {
  /** Repo-relative path -> file content served by the raw fetcher. */
  files: Record<string, string>;
  defaultBranch?: string;
  isPrivate?: boolean;
  archived?: boolean;
  treeTruncated?: boolean;
  /** Tree paths present but whose raw fetch fails. */
  unfetchable?: string[];
  /** Optional per-path size override for the tree entries. */
  sizes?: Record<string, number>;
  /** Commit sha returned by getRepo (defaults to a fixed fake distinct from the tree sha). */
  headSha?: string;
  /** Tree sha returned by getTree (defaults to a fixed fake distinct from the commit sha). */
  treeSha?: string;
};

export type FakeGithub = {
  github: GithubClient;
  fetcher: Fetcher;
  /** Every raw.githubusercontent.com URL the fetcher was asked for. */
  fetchedUrls: string[];
};

const FAKE_COMMIT_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FAKE_TREE_SHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/**
 * In-memory GithubClient + raw-file fetcher backed by the same repo map.
 * getRepo/getTree never hit the network; the fetcher only serves URLs of the
 * form https://raw.githubusercontent.com/<owner>/<repo>/<sha>/<path>.
 */
export function createFakeGithub(repos: Record<string, FakeRepoSpec>): FakeGithub {
  const fetchedUrls: string[] = [];

  const specFor = (owner: string, repo: string): FakeRepoSpec => {
    const spec = repos[`${owner}/${repo}`];
    if (!spec) {
      throw new GithubError("repo_not_found", "The repository could not be found.");
    }
    return spec;
  };

  const github: GithubClient = {
    async getRepo(owner, repo) {
      const spec = specFor(owner, repo);
      return {
        defaultBranch: spec.defaultBranch ?? "main",
        isPrivate: spec.isPrivate ?? false,
        archived: spec.archived ?? false,
        headSha: spec.headSha ?? FAKE_COMMIT_SHA,
      };
    },
    async getTree(owner, repo) {
      const spec = specFor(owner, repo);
      const unfetchable = new Set(spec.unfetchable ?? []);
      const entries = Object.keys(spec.files).map((path) => ({
        path,
        type: "blob" as const,
        size: spec.sizes?.[path] ?? Buffer.byteLength(spec.files[path], "utf8"),
      }));
      for (const path of unfetchable) {
        if (!spec.files[path]) {
          entries.push({ path, type: "blob" as const, size: spec.sizes?.[path] ?? 128 });
        }
      }
      return {
        sha: spec.treeSha ?? FAKE_TREE_SHA,
        truncated: spec.treeTruncated ?? false,
        entries,
      };
    },
  };

  const fetcher: Fetcher = async (url) => {
    fetchedUrls.push(url);
    const parsed = new URL(url);
    const segments = parsed.pathname.split("/").filter((segment) => segment !== "");
    // /<owner>/<repo>/<sha>/<path...>
    if (parsed.hostname !== "raw.githubusercontent.com" || segments.length < 4) {
      return { ok: false, reason: "blocked_url", message: "unexpected url" };
    }
    const [owner, repo, , ...pathSegments] = segments;
    const path = pathSegments.map((segment) => decodeURIComponent(segment)).join("/");
    const spec = repos[`${owner}/${repo}`];
    if (!spec || (spec.unfetchable ?? []).includes(path) || spec.files[path] === undefined) {
      return { ok: false, reason: "network_error", message: "no such file" };
    }
    return okResult(url, spec.files[path]);
  };

  return { github, fetcher, fetchedUrls };
}
