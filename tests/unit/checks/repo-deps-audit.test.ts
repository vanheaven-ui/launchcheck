import { describe, expect, it } from "vitest";
import { depsAuditCheck } from "@/lib/scanner/checks/repo/deps-audit";
import type { Fetcher } from "@/lib/scanner/types";
import { createFakeOsv } from "../../helpers/fake-osv";
import { okResult } from "../../helpers/fetcher";
import { makeRepoContext } from "../../helpers/repo";

const SHA = "0123456789abcdef0123456789abcdef01234567";
const LOCK_URL = `https://raw.githubusercontent.com/acme/app/${SHA}/package-lock.json`;
const YARN_URL = `https://raw.githubusercontent.com/acme/app/${SHA}/yarn.lock`;

const LOCKFILE = JSON.stringify({
  name: "app",
  lockfileVersion: 3,
  packages: {
    "": { name: "app" },
    "node_modules/lodash": { version: "4.17.20" },
    "node_modules/react": { version: "18.3.1" },
  },
});

function lockfileFetcher(
  body: string | Buffer = LOCKFILE,
  options: { truncated?: boolean; lockPath?: string } = {},
) {
  const lockPath = options.lockPath ?? "package-lock.json";
  const lockUrl = `https://raw.githubusercontent.com/acme/app/${SHA}/${lockPath}`;
  const seen: string[] = [];
  const fetcher: Fetcher = async (url) => {
    seen.push(url);
    if (url === lockUrl) {
      return okResult(url, typeof body === "string" ? body : body.toString("utf8"), {
        truncated: options.truncated,
      });
    }
    return { ok: false, reason: "network_error", message: "no route" };
  };
  return { fetcher, seen };
}

describe("repo.deps.audit", () => {
  it("returns no findings when there is no lockfile", async () => {
    const ctx = makeRepoContext({}, { osv: createFakeOsv().osv });
    ctx.repo.tree = [{ path: "src/index.ts", size: 10 }];
    expect(await depsAuditCheck.run(ctx)).toEqual([]);
  });

  it("emits a high-severity finding for a vulnerable package", async () => {
    const osv = createFakeOsv({
      vulnsByPackage: { "lodash@4.17.20": ["GHSA-lodash-1"] },
      vulnDetails: {
        "GHSA-lodash-1": { id: "GHSA-lodash-1", severity: "high" },
      },
    });
    const { fetcher, seen } = lockfileFetcher();
    const ctx = makeRepoContext(
      {},
      {
        fetch: fetcher,
        osv: osv.osv,
      },
    );
    // Inject the lockfile into the tree only (not fetched files).
    ctx.repo.tree = [
      { path: "package-lock.json", size: LOCKFILE.length },
      { path: "package.json", size: 10 },
    ];
    const findings = await depsAuditCheck.run(ctx);
    const vuln = findings.find((f) => f.severity === "high");
    expect(vuln).toBeDefined();
    expect(vuln?.title).toBe("1 dependencies have known high vulnerabilities");
    expect(vuln?.evidence).toContain("lodash@4.17.20 (GHSA-lodash-1)");
    expect(vuln?.location).toBe(`https://github.com/acme/app/blob/${SHA}/package-lock.json`);
    // The raw fetch used the commit sha and an encoded path.
    expect(seen).toEqual([LOCK_URL]);
  });

  it("groups mixed severities into one finding per tier", async () => {
    const osv = createFakeOsv({
      vulnsByPackage: {
        "lodash@4.17.20": ["V-CRIT", "V-MED"],
        "react@18.3.1": ["V-LOW"],
      },
      vulnDetails: {
        "V-CRIT": { id: "V-CRIT", severity: "critical" },
        "V-MED": { id: "V-MED", severity: "medium" },
        "V-LOW": { id: "V-LOW", severity: "low" },
      },
    });
    const { fetcher } = lockfileFetcher();
    const ctx = makeRepoContext({}, { fetch: fetcher, osv: osv.osv });
    ctx.repo.tree = [{ path: "package-lock.json", size: LOCKFILE.length }];
    const findings = await depsAuditCheck.run(ctx);
    const severities = findings.filter((f) => f.severity !== "info").map((f) => f.severity);
    expect(severities).toEqual(["critical", "medium", "low"]);
  });

  it("reports unknown severity as medium/low with the special title", async () => {
    const osv = createFakeOsv({
      vulnsByPackage: { "lodash@4.17.20": ["V-NOSEV"] },
      vulnDetails: { "V-NOSEV": { id: "V-NOSEV" } },
    });
    const { fetcher } = lockfileFetcher();
    const ctx = makeRepoContext({}, { fetch: fetcher, osv: osv.osv });
    ctx.repo.tree = [{ path: "package-lock.json", size: LOCKFILE.length }];
    const findings = await depsAuditCheck.run(ctx);
    const unknown = findings.find((f) => f.title.includes("unknown severity"));
    expect(unknown).toMatchObject({ severity: "medium", confidence: "low" });
  });

  it("returns an info finding when the lockfile fetch fails", async () => {
    const osv = createFakeOsv();
    const ctx = makeRepoContext(
      {},
      { fetch: async () => ({ ok: false, reason: "network_error", message: "x" }), osv: osv.osv },
    );
    ctx.repo.tree = [{ path: "package-lock.json", size: 100 }];
    const findings = await depsAuditCheck.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "info", checkId: "repo.deps.audit" });
    expect(osv.queryLog).toHaveLength(0);
  });

  it("returns an info finding when the lockfile exceeds 2 MB in the tree", async () => {
    const ctx = makeRepoContext({}, { osv: createFakeOsv().osv });
    ctx.repo.tree = [{ path: "package-lock.json", size: 3 * 1024 * 1024 }];
    const findings = await depsAuditCheck.run(ctx);
    expect(findings[0]?.evidence).toBe("lockfile_exceeds_2mb");
  });

  it("returns an info finding for an unsupported lockfile", async () => {
    const yarnBerry = "__metadata:\n  version: 6\n";
    const { fetcher, seen } = lockfileFetcher(yarnBerry, { lockPath: "yarn.lock" });
    const ctx = makeRepoContext({}, { fetch: fetcher, osv: createFakeOsv().osv });
    ctx.repo.tree = [{ path: "yarn.lock", size: yarnBerry.length }];
    const findings = await depsAuditCheck.run(ctx);
    expect(findings[0]?.evidence).toBe("lockfile_unsupported");
    expect(seen).toEqual([YARN_URL]);
  });

  it("returns an info finding for an unparseable lockfile", async () => {
    const garbage = "this is not json {{{";
    const { fetcher } = lockfileFetcher(garbage);
    const ctx = makeRepoContext({}, { fetch: fetcher, osv: createFakeOsv().osv });
    ctx.repo.tree = [{ path: "package-lock.json", size: garbage.length }];
    const findings = await depsAuditCheck.run(ctx);
    expect(findings[0]?.evidence).toBe("lockfile_unparseable");
  });

  it("returns an info finding when OSV is unavailable", async () => {
    const osv = createFakeOsv({ failQueryBatch: true });
    const { fetcher } = lockfileFetcher();
    const ctx = makeRepoContext({}, { fetch: fetcher, osv: osv.osv });
    ctx.repo.tree = [{ path: "package-lock.json", size: LOCKFILE.length }];
    const findings = await depsAuditCheck.run(ctx);
    expect(findings[0]?.evidence).toBe("osv_unavailable");
  });

  it("caps vulnerability detail lookups at 50 ids", async () => {
    // 60 packages each with one vuln -> 60 distinct ids, only 50 fetched.
    const packages: Record<string, { version: string }> = {};
    const vulnsByPackage: Record<string, string[]> = {};
    const vulnDetails: Record<string, { id: string; severity: "high" }> = {};
    for (let i = 0; i < 60; i++) {
      const name = `pkg${i}`;
      packages[`node_modules/${name}`] = { version: "1.0.0" };
      vulnsByPackage[`${name}@1.0.0`] = [`V-${i}`];
      vulnDetails[`V-${i}`] = { id: `V-${i}`, severity: "high" };
    }
    const lock = JSON.stringify({
      name: "app",
      lockfileVersion: 3,
      packages: { "": { name: "app" }, ...packages },
    });
    const osv = createFakeOsv({ vulnsByPackage, vulnDetails });
    const { fetcher } = lockfileFetcher(lock);
    const ctx = makeRepoContext({}, { fetch: fetcher, osv: osv.osv });
    ctx.repo.tree = [{ path: "package-lock.json", size: lock.length }];
    const findings = await depsAuditCheck.run(ctx);
    expect(osv.vulnLog).toHaveLength(50);
    // 10 unscored ids produce an info note.
    expect(findings.some((f) => f.severity === "info" && f.evidence.includes("not scored"))).toBe(
      true,
    );
  });

  it("never throws even when everything fails", async () => {
    const ctx = makeRepoContext(
      {},
      {
        fetch: async () => {
          throw new Error("boom");
        },
        osv: createFakeOsv().osv,
      },
    );
    ctx.repo.tree = [{ path: "package-lock.json", size: 10 }];
    const findings = await depsAuditCheck.run(ctx);
    expect(findings[0]?.severity).toBe("info");
  });
});
