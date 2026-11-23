import { Octokit } from "@octokit/rest";

/**
 * Minimal GitHub client for public repo scanning. Production uses Octokit
 * against api.github.com; tests inject an in-memory fake. The optional token
 * is only ever handed to Octokit — it is never logged, stored, or sent
 * anywhere else, and error messages never contain it or response bodies.
 */

export type GithubErrorCode = "repo_not_found" | "repo_rate_limited" | "repo_unreachable";

export class GithubError extends Error {
  readonly code: GithubErrorCode;

  constructor(code: GithubErrorCode, message: string) {
    super(message);
    this.name = "GithubError";
    this.code = code;
  }
}

export type RepoInfo = {
  defaultBranch: string;
  isPrivate: boolean;
  archived: boolean;
};

export type TreeEntry = {
  path: string;
  type: "blob" | "tree";
  size: number | null;
};

export type RepoTree = {
  sha: string;
  truncated: boolean;
  entries: TreeEntry[];
};

export type GithubClient = {
  getRepo(owner: string, repo: string): Promise<RepoInfo>;
  getTree(owner: string, repo: string, ref: string): Promise<RepoTree>;
};

const USER_AGENT = "LaunchCheckBot/1.0";
const REQUEST_TIMEOUT_MS = 10_000;

const ERROR_MESSAGES: Record<GithubErrorCode, string> = {
  repo_not_found: "The repository could not be found.",
  repo_rate_limited: "The GitHub rate limit was reached.",
  repo_unreachable: "The repository could not be reached.",
};

type OctokitErrorShape = {
  status?: number;
  message?: string;
  response?: { headers?: Record<string, string | undefined> };
};

function isRateLimited(error: OctokitErrorShape): boolean {
  const status = error.status;
  if (status !== 403 && status !== 429) {
    return false;
  }
  const remaining = error.response?.headers?.["x-ratelimit-remaining"];
  const message = error.message ?? "";
  return remaining === "0" || /rate limit/i.test(message);
}

/** Map any thrown value to a GithubError with a generic, secret-free message. */
function toGithubError(error: unknown): GithubError {
  if (error instanceof GithubError) {
    return error;
  }
  const shape = (typeof error === "object" && error !== null ? error : {}) as OctokitErrorShape;
  const status = shape.status;

  if (status === 404) {
    return new GithubError("repo_not_found", ERROR_MESSAGES.repo_not_found);
  }
  if (isRateLimited(shape)) {
    return new GithubError("repo_rate_limited", ERROR_MESSAGES.repo_rate_limited);
  }
  return new GithubError("repo_unreachable", ERROR_MESSAGES.repo_unreachable);
}

/**
 * Octokit-backed GithubClient. `octokit` may be injected for tests; when it is
 * absent a real Octokit instance is created with the optional token.
 */
export function createOctokitGithubClient(token?: string, octokit?: Octokit): GithubClient {
  const client = octokit ?? new Octokit({ auth: token, userAgent: USER_AGENT });

  return {
    async getRepo(owner: string, repo: string): Promise<RepoInfo> {
      try {
        const { data } = await client.rest.repos.get({
          owner,
          repo,
          request: { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) },
        });
        // Public repos only: a private repo is reported as not found even when
        // the token could read it.
        if (data.private) {
          throw new GithubError("repo_not_found", ERROR_MESSAGES.repo_not_found);
        }
        return {
          defaultBranch: data.default_branch,
          isPrivate: data.private,
          archived: data.archived,
        };
      } catch (error) {
        throw toGithubError(error);
      }
    },

    async getTree(owner: string, repo: string, ref: string): Promise<RepoTree> {
      try {
        const { data } = await client.rest.git.getTree({
          owner,
          repo,
          tree_sha: ref,
          recursive: "1",
          request: { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) },
        });
        const entries: TreeEntry[] = [];
        for (const item of data.tree) {
          if (item.type !== "blob" && item.type !== "tree") {
            continue;
          }
          entries.push({
            path: item.path,
            type: item.type,
            size: typeof item.size === "number" ? item.size : null,
          });
        }
        return { sha: data.sha, truncated: data.truncated, entries };
      } catch (error) {
        throw toGithubError(error);
      }
    },
  };
}
