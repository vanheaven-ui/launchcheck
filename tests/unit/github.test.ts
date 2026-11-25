import type { Octokit } from "@octokit/rest";
import { describe, expect, it, vi } from "vitest";
import { createOctokitGithubClient, GithubError } from "@/lib/scanner/github";

const TOKEN = "ghp_" + "t".repeat(30);

function octokitError(status: number, message: string, headers: Record<string, string> = {}) {
  return Object.assign(new Error(message), {
    status,
    response: { headers, status },
  });
}

function fakeOctokit(overrides: {
  getRepo?: (params: Record<string, unknown>) => Promise<unknown>;
  getBranch?: (params: Record<string, unknown>) => Promise<unknown>;
  getTree?: (params: Record<string, unknown>) => Promise<unknown>;
}) {
  return {
    rest: {
      repos: {
        get: vi.fn(overrides.getRepo ?? (async () => ({ data: {} }))),
        getBranch: vi.fn(
          overrides.getBranch ?? (async () => ({ data: { commit: { sha: "c".repeat(40) } } })),
        ),
      },
      git: { getTree: vi.fn(overrides.getTree ?? (async () => ({ data: {} }))) },
    },
  } as unknown as Octokit;
}

const REPO_DATA = {
  default_branch: "main",
  private: false,
  archived: false,
};

describe("createOctokitGithubClient", () => {
  it("maps repo metadata and requests with a 10s abort signal", async () => {
    const octokit = fakeOctokit({
      getRepo: async () => ({ data: REPO_DATA }),
    });
    const client = createOctokitGithubClient(TOKEN, octokit);
    const info = await client.getRepo("owner", "repo");
    expect(info).toEqual({
      defaultBranch: "main",
      isPrivate: false,
      archived: false,
      headSha: "c".repeat(40),
    });

    const call = (octokit.rest.repos.get as unknown as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call).toMatchObject({ owner: "owner", repo: "repo" });
    expect((call as { request?: { signal?: AbortSignal } }).request?.signal).toBeInstanceOf(
      AbortSignal,
    );

    // getBranch is called once with the default branch and an abort signal.
    const branchCall = (octokit.rest.repos.getBranch as unknown as ReturnType<typeof vi.fn>).mock
      .calls[0][0];
    expect(branchCall).toMatchObject({ owner: "owner", repo: "repo", branch: "main" });
    expect((branchCall as { request?: { signal?: AbortSignal } }).request?.signal).toBeInstanceOf(
      AbortSignal,
    );
    expect(
      (octokit.rest.repos.getBranch as unknown as ReturnType<typeof vi.fn>).mock.calls,
    ).toHaveLength(1);
  });

  it("requests the tree recursively with a 10s abort signal", async () => {
    const octokit = fakeOctokit({
      getTree: async () => ({
        data: {
          sha: "abc123",
          truncated: false,
          tree: [
            { path: "a.ts", type: "blob", size: 10 },
            { path: "src", type: "tree" },
            { path: "sub", type: "commit" },
            { type: "blob", size: 5 },
          ],
        },
      }),
    });
    const client = createOctokitGithubClient(TOKEN, octokit);
    const tree = await client.getTree("owner", "repo", "main");
    expect(tree.sha).toBe("abc123");
    expect(tree.entries).toEqual([
      { path: "a.ts", type: "blob", size: 10 },
      { path: "src", type: "tree", size: null },
    ]);

    const call = (octokit.rest.git.getTree as unknown as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call).toMatchObject({ owner: "owner", repo: "repo", tree_sha: "main", recursive: "1" });
    expect((call as { request?: { signal?: AbortSignal } }).request?.signal).toBeInstanceOf(
      AbortSignal,
    );
  });

  it("maps HTTP 404 to repo_not_found", async () => {
    const octokit = fakeOctokit({
      getRepo: async () => {
        throw octokitError(404, "Not Found");
      },
    });
    const client = createOctokitGithubClient(TOKEN, octokit);
    await expect(client.getRepo("o", "r")).rejects.toMatchObject({
      name: "GithubError",
      code: "repo_not_found",
    });
  });

  it("maps a private repo to repo_not_found even when readable", async () => {
    const octokit = fakeOctokit({
      getRepo: async () => ({ data: { ...REPO_DATA, private: true } }),
    });
    const client = createOctokitGithubClient(TOKEN, octokit);
    await expect(client.getRepo("o", "r")).rejects.toMatchObject({ code: "repo_not_found" });
    // getBranch must not be called for a private repo.
    expect(
      (octokit.rest.repos.getBranch as unknown as ReturnType<typeof vi.fn>).mock.calls,
    ).toHaveLength(0);
  });

  it("maps a getBranch 404 to repo_not_found", async () => {
    const octokit = fakeOctokit({
      getRepo: async () => ({ data: REPO_DATA }),
      getBranch: async () => {
        throw octokitError(404, "Branch not found");
      },
    });
    const client = createOctokitGithubClient(TOKEN, octokit);
    await expect(client.getRepo("o", "r")).rejects.toMatchObject({
      code: "repo_not_found",
      message: expect.not.stringContaining(TOKEN),
    });
  });

  it("maps a getBranch rate-limit error to repo_rate_limited", async () => {
    const octokit = fakeOctokit({
      getRepo: async () => ({ data: REPO_DATA }),
      getBranch: async () => {
        throw octokitError(429, "You have exceeded a secondary rate limit");
      },
    });
    const client = createOctokitGithubClient(TOKEN, octokit);
    await expect(client.getRepo("o", "r")).rejects.toMatchObject({
      code: "repo_rate_limited",
    });
  });

  it("maps 403 with x-ratelimit-remaining 0 to repo_rate_limited", async () => {
    const octokit = fakeOctokit({
      getRepo: async () => {
        throw octokitError(403, "API rate limit exceeded", { "x-ratelimit-remaining": "0" });
      },
    });
    const client = createOctokitGithubClient(TOKEN, octokit);
    await expect(client.getRepo("o", "r")).rejects.toMatchObject({
      code: "repo_rate_limited",
    });
  });

  it("maps a rate-limit message on 403/429 to repo_rate_limited", async () => {
    for (const status of [403, 429]) {
      const octokit = fakeOctokit({
        getRepo: async () => {
          throw octokitError(status, "You have exceeded a secondary rate limit");
        },
      });
      const client = createOctokitGithubClient(TOKEN, octokit);
      await expect(client.getRepo("o", "r")).rejects.toMatchObject({
        code: "repo_rate_limited",
      });
    }
  });

  it("maps other failures to repo_unreachable", async () => {
    const octokit = fakeOctokit({
      getRepo: async () => {
        throw octokitError(500, "Internal Server Error");
      },
    });
    const client = createOctokitGithubClient(TOKEN, octokit);
    await expect(client.getRepo("o", "r")).rejects.toMatchObject({
      code: "repo_unreachable",
    });
  });

  it("never puts the token or response bodies in error messages", async () => {
    const octokit = fakeOctokit({
      getRepo: async () => {
        throw octokitError(403, `Forbidden for token ${TOKEN} body={"secret":"x"}`);
      },
      getTree: async () => {
        throw new Error("socket hangup");
      },
    });
    const client = createOctokitGithubClient(TOKEN, octokit);
    for (const call of [() => client.getRepo("o", "r"), () => client.getTree("o", "r", "main")]) {
      try {
        await call();
        expect.unreachable("should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(GithubError);
        const message = (error as Error).message;
        expect(message).not.toContain(TOKEN);
        expect(message).not.toContain("secret");
        expect(message).not.toContain("body=");
      }
    }
  });
});
