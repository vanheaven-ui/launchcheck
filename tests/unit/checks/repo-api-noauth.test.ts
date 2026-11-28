import { describe, expect, it } from "vitest";
import { apiNoauthCheck } from "@/lib/scanner/checks/repo/api-noauth";
import type { RepoFile } from "@/lib/scanner/types";
import { makeRepoContext } from "../../helpers/repo";

function file(path: string, text: string): RepoFile {
  return { path, text, truncated: false };
}

const ROUTE = "app/api/items/route.ts";
const DATA = 'import { db } from "@/lib/db"; await db.insert(items).values(data);';

describe("repo.api.noauth", () => {
  it("flags a data-touching POST route with no auth as medium/low", async () => {
    const findings = await apiNoauthCheck.run(
      makeRepoContext({ files: [file(ROUTE, `export async function POST() { ${DATA} }`)] }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "medium",
      confidence: "low",
      title: "Possible unauthenticated endpoint",
    });
    expect(findings[0].evidence).toContain("POST");
    expect(findings[0].evidence).toContain(ROUTE);
  });

  it("flags a GET-only route as low", async () => {
    const findings = await apiNoauthCheck.run(
      makeRepoContext({ files: [file(ROUTE, `export async function GET() { ${DATA} }`)] }),
    );
    expect(findings[0].severity).toBe("low");
  });

  it("flags server actions as medium", async () => {
    const findings = await apiNoauthCheck.run(
      makeRepoContext({
        files: [file("app/actions.ts", `"use server"; ${DATA}`)],
      }),
    );
    expect(findings[0]).toMatchObject({ severity: "medium" });
    expect(findings[0].evidence).toContain("server action");
  });

  it("does not flag when an auth signal is present", async () => {
    for (const auth of [
      "await auth()",
      "getServerSession()",
      "supabase.auth.getUser()",
      'headers.get("authorization")',
      "jwt.verify(t)",
    ]) {
      const findings = await apiNoauthCheck.run(
        makeRepoContext({
          files: [file(ROUTE, `export async function POST() { ${auth}; ${DATA} }`)],
        }),
      );
      expect(findings).toEqual([]);
    }
  });

  it("does not flag data signals absent", async () => {
    const findings = await apiNoauthCheck.run(
      makeRepoContext({
        files: [file(ROUTE, "export async function POST() { return Response.json({}); }")],
      }),
    );
    expect(findings).toEqual([]);
  });

  it("annotates the title when middleware mentions auth", async () => {
    const findings = await apiNoauthCheck.run(
      makeRepoContext({
        tree: [{ path: "middleware.ts", size: 10 }],
        files: [
          file("middleware.ts", "export function middleware() { /* auth session */ }"),
          file(ROUTE, `export async function POST() { ${DATA} }`),
        ],
      }),
    );
    expect(findings[0].title).toContain("middleware may protect this route");
  });

  it("skips webhook/stripe, auth, health, og, and test paths", async () => {
    const skipped = [
      "app/api/webhooks/stripe/route.ts",
      "app/api/auth/session/route.ts",
      "app/api/[...nextauth]/route.ts",
      "app/api/health/route.ts",
      "app/api/healthz/route.ts",
      "app/api/sitemap/route.ts",
      "app/api/robots/route.ts",
      "app/api/og/route.tsx",
      "app/api/opengraph/route.tsx",
      "tests/api/items.test.ts",
    ];
    for (const path of skipped) {
      const findings = await apiNoauthCheck.run(
        makeRepoContext({ files: [file(path, `export async function POST() { ${DATA} }`)] }),
      );
      expect(findings, path).toEqual([]);
    }
  });

  it("caps findings at 10", async () => {
    const files = Array.from({ length: 14 }, (_, i) =>
      file(`app/api/r${i}/route.ts`, `export async function POST() { ${DATA} }`),
    );
    const findings = await apiNoauthCheck.run(makeRepoContext({ files }));
    expect(findings).toHaveLength(10);
  });

  it("completes a 2MB pathological file under 1s", async () => {
    const pathological = "export async function ".repeat(200_000);
    const start = Date.now();
    await apiNoauthCheck.run(makeRepoContext({ files: [file(ROUTE, pathological + DATA)] }));
    expect(Date.now() - start).toBeLessThan(1000);
  });
});
