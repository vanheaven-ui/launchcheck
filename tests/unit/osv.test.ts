import { describe, expect, it } from "vitest";
import { createOsvClient, OsvError } from "@/lib/scanner/osv";

type FetchCall = { url: string; init: RequestInit };

function fakeFetch(handler: (url: string, init: RequestInit) => Response | Promise<Response>): {
  fetchImpl: typeof fetch;
  calls: FetchCall[];
} {
  const calls: FetchCall[] = [];
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
    const u = typeof url === "string" ? url : url instanceof URL ? url.href : url.url;
    calls.push({ url: u, init: init ?? {} });
    return handler(u, init ?? {});
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("createOsvClient.queryBatch", () => {
  it("posts to /v1/querybatch on api.osv.dev with a timeout signal and no auth", async () => {
    const { fetchImpl, calls } = fakeFetch(async () =>
      jsonResponse({ results: [{ vulns: [{ id: "GHSA-1" }] }, { vulns: null }] }),
    );
    const client = createOsvClient(fetchImpl);
    const results = await client.queryBatch([
      { name: "lodash", version: "4.17.20" },
      { name: "react", version: "18.3.1" },
    ]);
    expect(results).toEqual([["GHSA-1"], []]);

    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call.url).toBe("https://api.osv.dev/v1/querybatch");
    expect(call.init.method).toBe("POST");
    expect(call.init.signal).toBeInstanceOf(AbortSignal);
    const headers = call.init.headers as Record<string, string>;
    expect(headers["User-Agent"]).toBe("LaunchCheckBot/1.0");
    expect(headers["Content-Type"]).toBe("application/json");
    expect(Object.keys(headers).every((k) => k === "User-Agent" || k === "Content-Type")).toBe(
      true,
    );
    const body = JSON.parse(call.init.body as string) as {
      queries: { package: { name: string; ecosystem: string }; version: string }[];
    };
    expect(body.queries).toEqual([
      { package: { name: "lodash", ecosystem: "npm" }, version: "4.17.20" },
      { package: { name: "react", ecosystem: "npm" }, version: "18.3.1" },
    ]);
  });

  it("chunks requests at 500 and preserves input order", async () => {
    const { fetchImpl, calls } = fakeFetch(async (_url, init) => {
      const body = JSON.parse(init.body as string) as {
        queries: { version: string }[];
      };
      return jsonResponse({
        results: body.queries.map((q) => ({
          vulns: q.version === "0.0.0" ? [{ id: `VULN-${q.version}` }] : [],
        })),
      });
    });
    const client = createOsvClient(fetchImpl);
    const queries = Array.from({ length: 501 }, (_, i) => ({
      name: "pkg",
      version: `${i}.0.0`,
    }));
    const results = await client.queryBatch(queries);
    expect(results).toHaveLength(501);
    expect(results[0]).toEqual(["VULN-0.0.0"]);
    expect(results[1]).toEqual([]);
    expect(calls).toHaveLength(2);
    const firstBody = JSON.parse(calls[0].init.body as string) as { queries: unknown[] };
    const secondBody = JSON.parse(calls[1].init.body as string) as { queries: unknown[] };
    expect(firstBody.queries).toHaveLength(500);
    expect(secondBody.queries).toHaveLength(1);
  });

  it("throws OsvError on non-200, invalid JSON, and oversized bodies", async () => {
    for (const handler of [
      async () => new Response("nope", { status: 500 }),
      async () => new Response("not json", { status: 200 }),
      async () => new Response("x".repeat(2 * 1024 * 1024 + 1), { status: 200 }),
    ]) {
      const { fetchImpl } = fakeFetch(handler);
      const client = createOsvClient(fetchImpl);
      await expect(client.queryBatch([{ name: "a", version: "1.0.0" }])).rejects.toBeInstanceOf(
        OsvError,
      );
    }
  });

  it("never leaks the response body into error messages", async () => {
    const { fetchImpl } = fakeFetch(
      async () => new Response("SECRET-BODY-CONTENT", { status: 500 }),
    );
    const client = createOsvClient(fetchImpl);
    try {
      await client.queryBatch([{ name: "a", version: "1.0.0" }]);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(OsvError);
      expect((error as Error).message).not.toContain("SECRET-BODY-CONTENT");
    }
  });
});

describe("createOsvClient.getVuln", () => {
  it("returns null for ids that fail the safety regex", async () => {
    const { fetchImpl, calls } = fakeFetch(async () => jsonResponse({}));
    const client = createOsvClient(fetchImpl);
    for (const bad of ["../x", "a/b", "", "x".repeat(101), "id with space"]) {
      expect(await client.getVuln(bad)).toBeNull();
    }
    expect(calls).toHaveLength(0);
  });

  it("fetches /v1/vulns/<id> encoded and normalizes severity", async () => {
    const { fetchImpl, calls } = fakeFetch(async () =>
      jsonResponse({
        id: "GHSA-abc",
        summary: "Bad thing",
        database_specific: { severity: "MODERATE" },
      }),
    );
    const client = createOsvClient(fetchImpl);
    const vuln = await client.getVuln("GHSA-abc.def:1");
    expect(vuln).toEqual({ id: "GHSA-abc", summary: "Bad thing", severity: "medium" });
    expect(calls[0].url).toBe("https://api.osv.dev/v1/vulns/GHSA-abc.def%3A1");
    expect(calls[0].init.method).toBe("GET");
  });

  it("maps CRITICAL/HIGH/LOW and leaves unknown severities undefined", async () => {
    const severities: [string, string | undefined][] = [
      ["CRITICAL", "critical"],
      ["HIGH", "high"],
      ["MODERATE", "medium"],
      ["MEDIUM", "medium"],
      ["LOW", "low"],
      ["UNKNOWN", undefined],
    ];
    for (const [raw, expected] of severities) {
      const { fetchImpl } = fakeFetch(async () =>
        jsonResponse({ id: "V-1", database_specific: { severity: raw } }),
      );
      const client = createOsvClient(fetchImpl);
      const vuln = await client.getVuln("V-1");
      expect(vuln?.severity).toBe(expected);
    }
  });

  it("returns null on 404", async () => {
    const { fetchImpl } = fakeFetch(async () => new Response("nf", { status: 404 }));
    const client = createOsvClient(fetchImpl);
    expect(await client.getVuln("GHSA-missing")).toBeNull();
  });
});
