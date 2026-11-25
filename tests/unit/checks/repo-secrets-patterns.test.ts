import { describe, expect, it } from "vitest";
import { repoSecretsPatternsCheck } from "@/lib/scanner/checks/repo/secrets-patterns";
import { makeRepoContext, makeRepoSnapshot } from "../../helpers/repo";

const STRIPE_KEY = "sk" + "_live_" + "x".repeat(24);
const STRIPE_TEST_KEY = "sk" + "_test_" + "y".repeat(20);

const b64url = (value: string) => Buffer.from(value, "utf8").toString("base64url");
function fakeJwt(payload: Record<string, unknown>): string {
  return `${b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.${b64url(JSON.stringify(payload))}.${b64url("sig")}`;
}
const SERVICE_JWT = fakeJwt({ role: "service_role", iss: "https://x.supabase.co/auth/v1" });
const ANON_JWT = fakeJwt({ role: "anon", iss: "https://x.supabase.co/auth/v1" });

const SHA = makeRepoSnapshot().sha;
const blob = (path: string) => `https://github.com/acme/app/blob/${SHA}/${path}`;

describe("repo.secrets.patterns", () => {
  it("flags a Stripe live key with redacted evidence and blob location", async () => {
    const text = `line one\nconst key = "${STRIPE_KEY}";\n`;
    const ctx = makeRepoContext({
      files: [{ path: "src/config.ts", text, truncated: false }],
    });
    const findings = await repoSecretsPatternsCheck.run(ctx);
    const stripe = findings.find((f) => f.title.includes("Stripe live"));
    expect(stripe).toMatchObject({
      severity: "critical",
      confidence: "high",
      checkId: "repo.secrets.patterns",
    });
    expect(stripe?.title).toBe("Stripe live secret key found in repository");
    // redactSecret keeps the first 4 and last 2 characters.
    expect(stripe?.evidence).toMatch(/^Stripe live secret key: sk_l\*+xx at src\/config\.ts:2$/);
    expect(stripe?.evidence).not.toContain(STRIPE_KEY);
    expect(stripe?.location).toBe(blob("src/config.ts"));
  });

  it("flags a service_role JWT as critical but ignores an anon JWT", async () => {
    const text = `const a = "${SERVICE_JWT}";\nconst b = "${ANON_JWT}";\n`;
    const ctx = makeRepoContext({
      files: [{ path: "src/supabase.ts", text, truncated: false }],
    });
    const findings = await repoSecretsPatternsCheck.run(ctx);
    const jwt = findings.filter((f) => f.title.includes("service_role"));
    expect(jwt).toHaveLength(1);
    expect(jwt[0]).toMatchObject({ severity: "critical", confidence: "high" });
    expect(jwt[0].evidence).toContain("src/supabase.ts:1");
    expect(jwt[0].evidence).not.toContain(SERVICE_JWT);
    expect(findings.some((f) => f.evidence.includes(ANON_JWT))).toBe(false);
  });

  it("downgrades matches in test-like paths to low/low", async () => {
    for (const path of [
      "tests/keys.ts",
      "src/foo.spec.ts",
      "fixtures/sample.json",
      "mocks/data.ts",
      "docs/examples.ts",
    ]) {
      const ctx = makeRepoContext({
        files: [{ path, text: `const k = "${STRIPE_KEY}";`, truncated: false }],
      });
      const findings = await repoSecretsPatternsCheck.run(ctx);
      const stripe = findings.find((f) => f.title.includes("Stripe"));
      expect(stripe, path).toMatchObject({ severity: "low", confidence: "low" });
      expect(stripe?.title).toBe("Possible Stripe live secret key found in repository");
    }
  });

  it("does NOT downgrade .env.example files", async () => {
    const ctx = makeRepoContext({
      files: [{ path: "samples/.env.example", text: `KEY=${STRIPE_TEST_KEY}\n`, truncated: false }],
    });
    const findings = await repoSecretsPatternsCheck.run(ctx);
    const stripe = findings.find((f) => f.title.includes("Stripe test"));
    expect(stripe).toMatchObject({ severity: "medium", confidence: "high" });
    expect(stripe?.title).toBe("Stripe test secret key found in repository");
  });

  it("de-duplicates by pattern id and value across files", async () => {
    const ctx = makeRepoContext({
      files: [
        { path: "a.ts", text: `const k = "${STRIPE_KEY}";`, truncated: false },
        { path: "b.ts", text: `const k = "${STRIPE_KEY}";`, truncated: false },
      ],
    });
    const findings = await repoSecretsPatternsCheck.run(ctx);
    expect(findings.filter((f) => f.title.includes("Stripe live"))).toHaveLength(1);
  });

  it("caps findings at 20", async () => {
    const files = Array.from({ length: 25 }, (_, i) => ({
      path: `src/f${i}.ts`,
      text: `const k${i} = "sk${"_live_"}${String(i).padStart(20, "0")}";`,
      truncated: false,
    }));
    const ctx = makeRepoContext({ files });
    const findings = await repoSecretsPatternsCheck.run(ctx);
    expect(findings.length).toBeLessThanOrEqual(20);
  });

  it("computes the correct 1-based line number", async () => {
    const text = `a\nb\nc\n${STRIPE_KEY}\n`;
    const ctx = makeRepoContext({
      files: [{ path: "deep/path/key.txt", text, truncated: false }],
    });
    const findings = await repoSecretsPatternsCheck.run(ctx);
    const stripe = findings.find((f) => f.title.includes("Stripe live"));
    expect(stripe?.evidence).toContain("deep/path/key.txt:4");
    expect(stripe?.location).toBe(blob("deep/path/key.txt"));
  });
});
