const b64url = (value: string) => Buffer.from(value, "utf8").toString("base64url");

function fakeJwt(payload: Record<string, unknown>): string {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64url(JSON.stringify(payload));
  const signature = b64url("not-a-real-signature");
  return `${header}.${body}.${signature}`;
}

// Fake secrets are built at runtime so no secret-shaped literal exists in the
// repo; the fake GithubClient still serves the fully-assembled strings.
export const VULN_REPO_STRIPE_KEY = "sk" + "_live_" + "y".repeat(24);
const VULN_SERVICE_JWT = fakeJwt({
  role: "service_role",
  iss: "https://abcdefghijklmnopqrst.supabase.co/auth/v1",
  exp: 4_000_000_000,
});

/**
 * A vulnerable repo fixture: a committed .env with a fake Stripe live key,
 * a Supabase service_role JWT in source, and no .gitignore, lockfile, README,
 * or tests — so repo.env.committed, repo.secrets.patterns, and
 * repo.quality.basics all fire.
 */
export const vulnerableRepoFiles: Record<string, string> = {
  ".env": [
    `STRIPE_SECRET_KEY=${VULN_REPO_STRIPE_KEY}`,
    "SUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co",
    "DATABASE_URL=postgres://user:pass@db.example.com:5432/app",
    "",
  ].join("\n"),
  "package.json": JSON.stringify(
    {
      name: "vuln-app",
      private: true,
      scripts: { dev: "next dev", build: "next build" },
      dependencies: { next: "16.0.0" },
    },
    null,
    2,
  ),
  "src/index.ts": [
    'import { createClient } from "@supabase/supabase-js";',
    "",
    "// TODO: move this somewhere safe",
    `const serviceRoleKey = "${VULN_SERVICE_JWT}";`,
    "",
    'export const admin = createClient(process.env.SUPABASE_URL ?? "", serviceRoleKey);',
    "",
  ].join("\n"),
  "src/utils.ts": "export const add = (a: number, b: number) => a + b;\n",
};
