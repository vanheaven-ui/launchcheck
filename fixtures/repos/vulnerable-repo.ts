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
  // Stripe webhook handler with no constructEvent call.
  "app/api/webhooks/stripe/route.ts": [
    'import { NextResponse } from "next/server";',
    "",
    "export async function POST(request: Request) {",
    "  const body = await request.json();",
    '  if (body.type === "checkout.session.completed") {',
    "    // fulfill order",
    "  }",
    "  return NextResponse.json({ received: true });",
    "}",
    "",
  ].join("\n"),
  // Next.js route that writes to the db with no auth signal.
  "app/api/items/route.ts": [
    'import { db } from "@/lib/db";',
    'import { items } from "@/lib/schema";',
    "",
    "export async function POST(request: Request) {",
    "  const data = await request.json();",
    "  await db.insert(items).values(data);",
    "  return Response.json({ ok: true });",
    "}",
    "",
  ].join("\n"),
  // SQL migration creating public tables with no RLS and a permissive policy.
  "supabase/migrations/001_init.sql": [
    "create table if not exists public.notes (",
    "  id uuid primary key,",
    "  body text",
    ");",
    "",
    "create table public.profiles (",
    "  id uuid primary key,",
    "  email text",
    ");",
    "",
    "create policy notes_update on notes for update using (true) with check (true);",
    "",
  ].join("\n"),
  // package-lock v3 with an outdated package; the fake OSV client reports
  // vulnerabilities for it (no real network in tests).
  "package-lock.json": JSON.stringify(
    {
      name: "vuln-app",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "vuln-app" },
        "node_modules/lodash": { version: "4.17.20" },
        "node_modules/next": { version: "16.0.0" },
      },
    },
    null,
    2,
  ),
};
