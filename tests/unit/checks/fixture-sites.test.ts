import { afterEach, describe, expect, it } from "vitest";
import { persistFindings } from "@/lib/scanner/persist";
import { runSiteScan } from "@/lib/scanner/scan-site";
import { cleanSite } from "../../../fixtures/sites/clean-site";
import {
  VULN_ANON_JWT,
  VULN_SERVICE_JWT,
  VULN_STRIPE_KEY,
  vulnerableSite,
} from "../../../fixtures/sites/vulnerable-site";
import { type FixtureServer, startFixtureServer } from "../../helpers/fixture-server";
import { mockDb } from "../../helpers/mock-db";

let server: FixtureServer | null = null;

afterEach(async () => {
  await server?.close();
  server = null;
});

const FAKE_SECRETS = [VULN_STRIPE_KEY, VULN_SERVICE_JWT, VULN_ANON_JWT];

function expectNoFullSecrets(findings: { evidence: string; title: string; location?: string }[]) {
  const serialized = JSON.stringify(findings);
  for (const secret of FAKE_SECRETS) {
    expect(serialized).not.toContain(secret);
  }
}

describe("fixture sites through the real snapshot + full check registry", () => {
  it("vulnerable-site yields the expected Phase 2B and 2C findings", async () => {
    server = await startFixtureServer(vulnerableSite);
    const result = await runSiteScan({
      siteUrl: "http://fixture.example/",
      fetcher: server.fetcher,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const { findings } = result;

    // Phase 2B header/transport/cookie checks still fire.
    const ids = new Set(findings.map((f) => f.checkId));
    for (const id of [
      "site.headers.csp",
      "site.headers.frame",
      "site.headers.misc",
      "site.cookies",
      "site.https.redirect",
    ]) {
      expect(ids.has(id)).toBe(true);
    }

    // Phase 2C: the leaked Stripe live key is a critical bundle secret.
    const bundleSecrets = findings.filter((f) => f.checkId === "site.bundle.secrets");
    expect(bundleSecrets.some((f) => f.severity === "critical")).toBe(true);
    expectNoFullSecrets(bundleSecrets);

    // Phase 2C: the service_role JWT is critical; the anon JWT + project URL
    // produces the informational RLS finding.
    const supabase = findings.filter((f) => f.checkId === "site.backend.supabase");
    expect(
      supabase.some(
        (f) =>
          f.severity === "critical" &&
          f.title === "A Supabase service role key appears in public code",
      ),
    ).toBe(true);
    expect(supabase.some((f) => f.severity === "info")).toBe(true);

    // Phase 2C: Firebase config detected at medium/low.
    const firebase = findings.filter((f) => f.checkId === "site.backend.firebase");
    expect(firebase).toHaveLength(1);
    expect(firebase[0]).toMatchObject({ severity: "medium", confidence: "low" });

    // No full secret value appears in ANY finding field.
    expectNoFullSecrets(findings);

    // Persisting through the real persistFindings stores no full secret.
    const { db, insertedRows } = mockDb();
    await persistFindings(db, "scan-fixture", findings, { scope: "site" });
    const stored = JSON.stringify(insertedRows);
    for (const secret of FAKE_SECRETS) {
      expect(stored).not.toContain(secret);
    }
  });

  it("clean-site yields only the unavoidable plain-HTTP finding", async () => {
    server = await startFixtureServer(cleanSite);
    const result = await runSiteScan({
      siteUrl: "http://fixture.example/",
      fetcher: server.fetcher,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    // The fixture server is plain HTTP, so site.https.redirect correctly
    // fires; every other non-info finding must stay quiet (publishable keys
    // and browser keys are public by design and must not be flagged).
    const nonInfo = result.findings.filter((f) => f.severity !== "info");
    expect(nonInfo.map((f) => f.checkId)).toEqual(["site.https.redirect"]);
  });
});
