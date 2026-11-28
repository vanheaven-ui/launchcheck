import { type OsvClient, OsvError, type OsvSeverity, type OsvVuln } from "@/lib/scanner/osv";

export type FakeOsvOptions = {
  /** "name@version" -> vulnerability ids returned by queryBatch. */
  vulnsByPackage?: Record<string, string[]>;
  /** vulnerability id -> advisory detail (null = unknown id). */
  vulnDetails?: Record<string, OsvVuln | null>;
  /** When true, queryBatch throws OsvError. */
  failQueryBatch?: boolean;
  /** When true, every getVuln call throws OsvError. */
  failGetVuln?: boolean;
};

export type FakeOsv = {
  osv: OsvClient;
  /** Every queryBatch call's package list. */
  queryLog: { name: string; version: string }[][];
  /** Every getVuln id requested, in order. */
  vulnLog: string[];
};

/**
 * In-memory OsvClient for tests: no network. Vulnerabilities are keyed by
 * "name@version"; advisory details default to a medium-severity entry.
 */
export function createFakeOsv(options: FakeOsvOptions = {}): FakeOsv {
  const vulnsByPackage = options.vulnsByPackage ?? {};
  const vulnDetails = options.vulnDetails ?? {};
  const queryLog: { name: string; version: string }[][] = [];
  const vulnLog: string[] = [];

  const osv: OsvClient = {
    async queryBatch(queries) {
      queryLog.push(queries.map((q) => ({ ...q })));
      if (options.failQueryBatch) {
        throw new OsvError("OSV could not be reached.");
      }
      return queries.map((q) => [...(vulnsByPackage[`${q.name}@${q.version}`] ?? [])]);
    },
    async getVuln(id) {
      vulnLog.push(id);
      if (options.failGetVuln) {
        throw new OsvError("OSV could not be reached.");
      }
      if (id in vulnDetails) {
        return vulnDetails[id];
      }
      // Default: a medium-severity advisory so tests get deterministic output.
      const vuln: OsvVuln = { id, severity: "medium" as OsvSeverity };
      return vuln;
    },
  };

  return { osv, queryLog, vulnLog };
}
