/**
 * A clean repo fixture: .gitignore that ignores env files, a README, a
 * lockfile, a test file, and a .env.example with placeholders only. Repo
 * checks should produce no security/reliability findings for it.
 */
export const cleanRepoFiles: Record<string, string> = {
  ".gitignore": ["node_modules/", "dist/", ".env", "*.env", "!.env.example", ".next/", ""].join(
    "\n",
  ),
  ".env.example": [
    "STRIPE_SECRET_KEY=your-stripe-test-key",
    "SUPABASE_URL=https://your-project.supabase.co",
    "DATABASE_URL=postgres://user:password@localhost:5432/app",
    "",
  ].join("\n"),
  "README.md": "# Clean App\n\nA small example app used by scanner tests.\n",
  "package.json": JSON.stringify(
    {
      name: "clean-app",
      private: true,
      scripts: { dev: "next dev", test: "vitest run" },
    },
    null,
    2,
  ),
  "pnpm-lock.yaml": [
    "lockfileVersion: '9.0'",
    "settings:",
    "  autoInstallPeers: true",
    "packages:",
    "  react@18.3.1:",
    "    resolution: {integrity: sha512-fakeintegrity}",
    "",
  ].join("\n"),
  // package-lock takes priority over pnpm-lock in the audit; keep it clean.
  "package-lock.json": JSON.stringify(
    {
      name: "clean-app",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "clean-app" },
        "node_modules/react": { version: "18.3.1" },
      },
    },
    null,
    2,
  ),
  // Stripe webhook that verifies the signature properly.
  "app/api/webhooks/stripe/route.ts": [
    'import { NextResponse } from "next/server";',
    'import Stripe from "stripe";',
    "",
    'const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? "");',
    "",
    "export async function POST(request: Request) {",
    '  const signature = request.headers.get("stripe-signature") ?? "";',
    "  const body = await request.text();",
    '  const event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET ?? "");',
    '  if (event.type === "checkout.session.completed") {',
    "    // fulfill order",
    "  }",
    "  return NextResponse.json({ received: true });",
    "}",
    "",
  ].join("\n"),
  // Authenticated route: auth() runs before any db access.
  "app/api/items/route.ts": [
    'import { auth } from "@/lib/auth";',
    'import { db } from "@/lib/db";',
    'import { items } from "@/lib/schema";',
    "",
    "export async function POST(request: Request) {",
    "  const session = await auth();",
    "  if (!session?.user) {",
    '    return Response.json({ error: "unauthorized" }, { status: 401 });',
    "  }",
    "  const data = await request.json();",
    "  await db.insert(items).values(data);",
    "  return Response.json({ ok: true });",
    "}",
    "",
  ].join("\n"),
  // Public health route with no data access.
  "app/api/health/route.ts": [
    "export async function GET() {",
    '  return Response.json({ status: "ok" });',
    "}",
    "",
  ].join("\n"),
  // Migration enabling RLS on every table with a scoped policy.
  "supabase/migrations/001_init.sql": [
    "create table public.notes (",
    "  id uuid primary key,",
    "  body text",
    ");",
    "",
    "alter table public.notes enable row level security;",
    "",
    "create policy notes_select_own on notes for select using (auth.uid() = user_id);",
    "",
  ].join("\n"),
  "src/index.ts": 'export const greeting = "hello";\n',
  "src/utils.test.ts": [
    'import { describe, expect, it } from "vitest";',
    'import { greeting } from "./index";',
    "",
    'describe("greeting", () => {',
    '  it("is a string", () => {',
    '    expect(typeof greeting).toBe("string");',
    "  });",
    "});",
    "",
  ].join("\n"),
};
