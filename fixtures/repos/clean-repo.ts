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
  "pnpm-lock.yaml": "lockfileVersion: '9.0'\nsettings:\n  autoInstallPeers: true\n",
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
