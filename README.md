# LaunchCheck

LaunchCheck scans a live site URL and/or a public GitHub repo for launch-readiness risks and produces a plain-English, severity-ranked report of *potential* issues. It never claims a site or repo is secure.

## Setup

1. Install [pnpm](https://pnpm.io/) (this repo pins `pnpm@10.33.0`).
2. Copy env template and fill required values:

```bash
cp .env.example .env.local
```

Required for local app/db usage:

- `DATABASE_URL` — Neon Postgres connection string
- `NEXT_PUBLIC_APP_URL` — usually `http://localhost:3000`

3. Install and run:

```bash
pnpm install
pnpm db:migrate   # applies drizzle/ migrations (needs DATABASE_URL)
pnpm dev
```

## How the scan pipeline works (Phase 3A)

When a scan is requested, the Inngest function `scan.run` executes these steps:

1. `validate-and-resolve` — re-validates the stored URLs.
2. `mark-running` — marks the scan as running.
3. `scan-site` *(site scans only)* — inside a single step it:
   - fetches the home page once through the SSRF-safe fetcher (`safeFetch`),
   - fetches `/robots.txt` once and respects `Disallow` rules for `LaunchCheckBot`,
   - discovers up to 15 same-origin `<script src>` / `modulepreload` URLs and fetches
     them at concurrency 4 within a 25-second budget,
   - runs the registered site checks (`lib/scanner/registry.ts`) in parallel with a
     5-second per-check timeout — a failing check becomes a `check_errored` info
     finding and never fails the scan,
   - replaces the scan's `site.` findings rows and returns only `{ findingCount }`.
4. `scan-repo` *(repo scans only)* — inside a single step it:
   - reads repo metadata and the file tree through Octokit (`api.github.com`),
   - fetches selected text files from `raw.githubusercontent.com` through the same
     SSRF-safe fetcher (public repos only; a private repo is treated as not found),
   - runs the registered repo checks (`lib/scanner/repo-registry.ts`),
   - replaces the scan's `repo.` findings rows and returns only `{ findingCount }`.
     In `both` mode an unreadable repo becomes one `info` finding instead of
     failing the scan; in `repo` mode it fails with `repo_unreachable`.
5. `finalize` — marks the scan completed.

Finding persistence is scoped per step: `persistFindings(..., { scope: "site" })`
deletes only `site.*` check rows and `{ scope: "repo" }` only `repo.*`, so the two
steps never delete each other's findings and retries stay idempotent.

## Implemented site checks (Phase 2)

| Check | What it does |
|---|---|
| `site.headers.hsts` | Missing or weak `Strict-Transport-Security` |
| `site.headers.csp` | Missing, report-only, or unsafe-script CSP |
| `site.headers.frame` | Missing `X-Frame-Options` / `frame-ancestors` |
| `site.headers.misc` | Missing `X-Content-Type-Options` / `Referrer-Policy` |
| `site.https.redirect` | HTTP does not redirect to HTTPS |
| `site.cookies` | Cookies missing `Secure` / `HttpOnly` / `SameSite` |
| `site.bundle.secrets` | Regex scan of HTML + same-origin JS for leaked credentials (redacted evidence only) |
| `site.backend.supabase` | Supabase project URL / JWT detection; `service_role` is critical, `anon` + project URL is informational (RLS review) |
| `site.backend.firebase` | Firebase config detection for manual Security Rules review |
| `site.perf.basic` | Response time, HTML size, total script size, images without dimensions |

Phase 2A shipped the check framework, site snapshot, and persistence; Phase 2B
added the header/transport/cookie checks; Phase 2C added bundle secrets,
backend detection, and basic performance checks. Findings are stored with
secrets scrubbed (a defensive pass masks any full secret before insert) and
are surfaced on `/scan/<id>` as severity counts plus the top finding titles
once the scan completes; the full report arrives in a later phase.

## Implemented repo checks (Phase 3A)

| Check | What it does |
|---|---|
| `repo.env.committed` | Flags committed `.env`-style files (critical when a fetched file has real values) |
| `repo.secrets.patterns` | Regex scan of fetched repo files for leaked credentials plus Supabase `service_role` JWTs; test-like paths are down-ranked |
| `repo.quality.basics` | Missing README, lockfile, `.gitignore` (and env coverage), or tests |

### GitHub token (optional)

Repo scans work without a token at GitHub's low unauthenticated rate limit.
Set `GITHUB_TOKEN` (a read-only personal access token, no extra scopes) in
`.env.local` or the hosting provider to raise the limit. The token is only ever
handed to Octokit — it is never logged, stored, or sent to `raw.githubusercontent.com`
or the AI provider. Only **public** repositories are scanned; private repos are
treated as not found.

## Running a scan locally

Scans are queued through [Inngest](https://www.inngest.com/). To process them locally:

1. Start the Inngest dev server in a second terminal:

```bash
npx inngest-cli@latest dev
```

2. Point it at the app (default `http://localhost:3000/api/inngest`; the CLI usually syncs apps automatically — check `http://localhost:8288`).

3. Open `http://localhost:3000`, fill in the scan form, and submit. The app redirects to `/scan/<id>`, which polls every 2 seconds until the scan completes.

Notes:

- `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` are optional locally — an in-memory rate limiter (3 scans/hour/IP, 5 scans/day/domain) is used instead. They are **required in production**.
- `INNGEST_EVENT_KEY` / `INNGEST_SIGNING_KEY` are optional locally with the dev server; **required in production**.
- Apply new migrations with `pnpm db:migrate` after pulling schema changes (generate them with `pnpm db:generate`).

## Environment variables

See [`.env.example`](.env.example) for the full list. Phase 0 validates `DATABASE_URL` and `NEXT_PUBLIC_APP_URL` as required; other keys are optional until later phases enable their features.

## Scripts

| Script | Purpose |
|---|---|
| `pnpm dev` | Start the Next.js dev server |
| `pnpm build` | Production build |
| `pnpm start` | Run the production server |
| `pnpm lint` | Biome lint + format check |
| `pnpm typecheck` | TypeScript `tsc --noEmit` |
| `pnpm test` | Vitest unit tests |
| `pnpm test:e2e` | Playwright e2e tests |
| `pnpm db:generate` | Generate Drizzle migrations |
| `pnpm db:migrate` | Apply Drizzle migrations |

## Notes

- Reports describe potential issues only.
- All services used by this project must stay on free plans.
