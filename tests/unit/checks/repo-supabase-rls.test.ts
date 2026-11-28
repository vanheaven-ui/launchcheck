import { describe, expect, it } from "vitest";
import { supabaseRlsCheck } from "@/lib/scanner/checks/repo/supabase-rls";
import type { RepoFile } from "@/lib/scanner/types";
import { makeRepoContext } from "../../helpers/repo";

function sql(path: string, text: string): RepoFile {
  return { path, text, truncated: false };
}

function ctx(files: RepoFile[], treeTruncated = false) {
  return makeRepoContext({
    files,
    treeTruncated,
    tree: files.map((f) => ({ path: f.path, size: f.text.length })),
  });
}

describe("repo.supabase.rls", () => {
  it("flags tables without enable row level security", async () => {
    const findings = await supabaseRlsCheck.run(
      ctx([
        sql(
          "supabase/migrations/001.sql",
          "create table public.notes (id int);\ncreate table profiles (id int);",
        ),
      ]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "high",
      confidence: "high",
      title: "Possible tables without row level security",
    });
    expect(findings[0].evidence).toContain("notes");
    expect(findings[0].evidence).toContain("profiles");
  });

  it("handles quoted, mixed-case, and if-not-exists names", async () => {
    const findings = await supabaseRlsCheck.run(
      ctx([sql("m.sql", 'CREATE TABLE IF NOT EXISTS "Public"."MyTable" (id int);')]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].evidence).toContain("MyTable");
  });

  it("resolves every create-table identifier variant to the table name", async () => {
    const variants = [
      "create table MyTable (id int);",
      'CREATE TABLE IF NOT EXISTS "MyTable" (id int);',
      "create table public.MyTable (id int);",
      'create table public."MyTable" (id int);',
      'create table "public"."MyTable" (id int);',
      'CREATE TABLE IF NOT EXISTS Public."MyTable" (id int);',
    ];
    for (const statement of variants) {
      const findings = await supabaseRlsCheck.run(ctx([sql("m.sql", statement)]));
      expect(findings, statement).toHaveLength(1);
      expect(findings[0].evidence, statement).toContain("MyTable");
      expect(findings[0].evidence, statement).not.toContain("public");
    }
  });

  it("skips auth/storage schemas and temporary tables", async () => {
    const findings = await supabaseRlsCheck.run(
      ctx([
        sql(
          "m.sql",
          'create table auth.users (id int);\ncreate table "storage"."objects" (id int);\ncreate temporary table t (id int);',
        ),
      ]),
    );
    expect(findings).toEqual([]);
  });

  it("counts an unqualified lowercase enable for a quoted schema-qualified table", async () => {
    const findings = await supabaseRlsCheck.run(
      ctx([
        sql(
          "m.sql",
          'create table "public"."MyTable" (id int);\nalter table mytable enable row level security;',
        ),
      ]),
    );
    expect(findings).toEqual([]);
  });

  it("does not count RLS enabled for a different table", async () => {
    const findings = await supabaseRlsCheck.run(
      ctx([
        sql(
          "m.sql",
          'create table "public"."MyTable" (id int);\nalter table public.other enable row level security;',
        ),
      ]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].evidence).toContain("MyTable");
  });

  it("skips non-public schemas and temporary tables", async () => {
    const findings = await supabaseRlsCheck.run(
      ctx([
        sql(
          "m.sql",
          "create table auth.sessions (id int);\ncreate temporary table tmp (id int);\ncreate table public.ok (id int);\nalter table public.ok enable row level security;",
        ),
      ]),
    );
    expect(findings).toEqual([]);
  });

  it("counts an enable statement in a later file", async () => {
    const findings = await supabaseRlsCheck.run(
      ctx([
        sql("001.sql", "create table public.notes (id int);"),
        sql("002.sql", "alter table public.notes enable row level security;"),
      ]),
    );
    expect(findings).toEqual([]);
  });

  it("does not count an enable for a different table", async () => {
    const findings = await supabaseRlsCheck.run(
      ctx([
        sql(
          "m.sql",
          "create table public.notes (id int);\nalter table public.other enable row level security;",
        ),
      ]),
    );
    expect(findings).toHaveLength(1);
  });

  it("flags explicit disable row level security", async () => {
    const findings = await supabaseRlsCheck.run(
      ctx([sql("m.sql", "alter table public.notes disable row level security;")]),
    );
    expect(findings[0]).toMatchObject({
      severity: "high",
      title: "Row level security explicitly disabled",
    });
  });

  it("detects policy names quoted with double quotes, single quotes, and backticks", async () => {
    for (const quoted of ['"pol_double"', "'pol_single'", "`pol_backtick`"]) {
      const findings = await supabaseRlsCheck.run(
        ctx([
          sql(
            "m.sql",
            `create table public.notes (id int);\nalter table public.notes enable row level security;\n` +
              `create policy ${quoted} on notes for update using (true);`,
          ),
        ]),
      );
      const policy = findings.find((f) => f.title.includes("permissive"));
      expect(policy, quoted).toBeDefined();
      expect(policy?.evidence, quoted).toContain("notes");
    }
  });

  it("detects a backtick-quoted table name", async () => {
    const findings = await supabaseRlsCheck.run(
      ctx([sql("m.sql", "create table `notes` (id int);")]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].evidence).toContain("notes");
  });

  it("flags permissive write policies but ignores select-only", async () => {
    const findings = await supabaseRlsCheck.run(
      ctx([
        sql(
          "m.sql",
          "create table public.notes (id int);\nalter table public.notes enable row level security;\n" +
            "create policy p1 on notes for update using (true);\n" +
            "create policy p2 on notes for insert with check (true);\n" +
            "create policy p3 on notes for select using (true);",
        ),
      ]),
    );
    const policy = findings.find((f) => f.title.includes("permissive"));
    expect(policy).toMatchObject({ severity: "medium", confidence: "medium" });
    expect(policy?.evidence).toContain("p1");
    expect(policy?.evidence).toContain("p2");
    expect(policy?.evidence).not.toContain("p3");
  });

  it("drops confidence to medium when a tree .sql file was not fetched", async () => {
    const context = makeRepoContext({
      files: [sql("001.sql", "create table public.notes (id int);")],
      tree: [
        { path: "001.sql", size: 40 },
        { path: "002.sql", size: 40 }, // in tree but not fetched
      ],
    });
    const findings = await supabaseRlsCheck.run(context);
    expect(findings[0].confidence).toBe("medium");
  });

  it("drops confidence when the tree is truncated", async () => {
    const findings = await supabaseRlsCheck.run(
      ctx([sql("m.sql", "create table public.notes (id int);")], true),
    );
    expect(findings[0].confidence).toBe("medium");
  });

  it("caps table names at 10", async () => {
    const creates = Array.from(
      { length: 15 },
      (_, i) => `create table public.t${i} (id int);`,
    ).join("\n");
    const findings = await supabaseRlsCheck.run(ctx([sql("m.sql", creates)]));
    expect(findings[0].evidence).toContain("+5 more");
  });

  it("completes a 2MB pathological file under 1s", async () => {
    const pathological = "create table ".repeat(200_000) + "using (".repeat(100_000);
    const start = Date.now();
    await supabaseRlsCheck.run(ctx([sql("m.sql", pathological)]));
    expect(Date.now() - start).toBeLessThan(1000);
  });
});
