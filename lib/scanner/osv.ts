import { z } from "zod";

/**
 * Minimal OSV client for the repo dependency audit (Phase 3B).
 *
 * safeFetch is GET/HEAD only and the OSV batch query needs POST, so this is a
 * dedicated client against the fixed https://api.osv.dev host. The host is a
 * constant and never comes from input, so this is not an SSRF path. Requests
 * carry no credentials — only Content-Type and a User-Agent.
 */

const OSV_BASE_URL = "https://api.osv.dev";
const REQUEST_TIMEOUT_MS = 10_000;
const MAX_BODY_BYTES = 2 * 1024 * 1024;
const QUERY_BATCH_SIZE = 500;
const USER_AGENT = "LaunchCheckBot/1.0";
const VULN_ID_RE = /^[A-Za-z0-9._:-]{1,100}$/;

export type OsvSeverity = "critical" | "high" | "medium" | "low";

export type OsvVuln = {
  id: string;
  summary?: string;
  severity?: OsvSeverity;
};

export type OsvQuery = { name: string; version: string };

export type OsvClient = {
  /** Vulnerability ids per query, in input order (empty array = none). */
  queryBatch(queries: OsvQuery[]): Promise<string[][]>;
  /** Full advisory for one id, or null when unknown. */
  getVuln(id: string): Promise<OsvVuln | null>;
};

export class OsvError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OsvError";
  }
}

const queryBatchResponseSchema = z.object({
  results: z
    .array(
      z.object({
        vulns: z.array(z.object({ id: z.string() })).nullish(),
      }),
    )
    .nullish(),
});

const vulnResponseSchema = z.object({
  id: z.string(),
  summary: z.string().nullish(),
  database_specific: z.object({ severity: z.string().nullish() }).nullish(),
});

function normalizeSeverity(raw: string | null | undefined): OsvSeverity | undefined {
  switch ((raw ?? "").trim().toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MODERATE":
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return undefined;
  }
}

async function readJsonBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > MAX_BODY_BYTES) {
    throw new OsvError("OSV response was too large.");
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new OsvError("OSV returned an unreadable response.");
  }
}

/**
 * Production OsvClient over the global fetch. `fetchImpl` is injectable for
 * tests; every call still targets the fixed OSV host with a 10s timeout.
 */
export function createOsvClient(fetchImpl: typeof fetch = fetch): OsvClient {
  async function request(path: string, init: RequestInit): Promise<unknown> {
    let response: Response;
    try {
      response = await fetchImpl(`${OSV_BASE_URL}${path}`, {
        ...init,
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        headers: {
          "User-Agent": USER_AGENT,
          ...(init.body ? { "Content-Type": "application/json" } : {}),
        },
      });
    } catch {
      throw new OsvError("OSV could not be reached.");
    }
    if (!response.ok) {
      throw new OsvError("OSV request failed.");
    }
    return readJsonBody(response);
  }

  return {
    async queryBatch(queries: OsvQuery[]): Promise<string[][]> {
      const results: string[][] = [];
      for (let i = 0; i < queries.length; i += QUERY_BATCH_SIZE) {
        const chunk = queries.slice(i, i + QUERY_BATCH_SIZE);
        const body = await request("/v1/querybatch", {
          method: "POST",
          body: JSON.stringify({
            queries: chunk.map((query) => ({
              package: { name: query.name, ecosystem: "npm" },
              version: query.version,
            })),
          }),
        });
        const parsed = queryBatchResponseSchema.safeParse(body);
        if (!parsed.success) {
          throw new OsvError("OSV returned an unexpected response.");
        }
        for (const entry of parsed.data.results ?? []) {
          results.push((entry.vulns ?? []).map((vuln) => vuln.id));
        }
        // Pad when OSV returns fewer result rows than queries.
        while (results.length < i + chunk.length) {
          results.push([]);
        }
      }
      return results;
    },

    async getVuln(id: string): Promise<OsvVuln | null> {
      if (!VULN_ID_RE.test(id)) {
        return null;
      }
      let response: Response;
      try {
        response = await fetchImpl(`${OSV_BASE_URL}/v1/vulns/${encodeURIComponent(id)}`, {
          method: "GET",
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          headers: { "User-Agent": USER_AGENT },
        });
      } catch {
        throw new OsvError("OSV could not be reached.");
      }
      if (response.status === 404) {
        return null;
      }
      if (!response.ok) {
        throw new OsvError("OSV request failed.");
      }
      const parsed = vulnResponseSchema.safeParse(await readJsonBody(response));
      if (!parsed.success) {
        throw new OsvError("OSV returned an unexpected response.");
      }
      const vuln: OsvVuln = { id: parsed.data.id };
      if (parsed.data.summary) {
        vuln.summary = parsed.data.summary;
      }
      const severity = normalizeSeverity(parsed.data.database_specific?.severity);
      if (severity) {
        vuln.severity = severity;
      }
      return vuln;
    },
  };
}

/** Shared production client used by the scan pipeline. */
export const productionOsvClient: OsvClient = createOsvClient();
