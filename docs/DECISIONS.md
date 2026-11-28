# Decisions

## 2026-11-10 — Phase 0 foundation choices

| Decision | Reason |
|---|---|
| Use Biome instead of ESLint + Prettier | SPEC allows either; Biome is one tool and matches AGENTS.md |
| Keep `payments.user_id` and `scans.user_id` as UUID columns without FK to `users` | Auth tables are deferred to Phase 5; avoid orphan FKs |
| Enum columns for scan status, finding category/severity/confidence/effort, and payment status | Narrows invalid values at the DB layer while matching SPEC section 8 shapes |
| Validate env via `getEnv()` (lazy) rather than import-time parse | Lets lint/typecheck/unit tests run without loading secrets; CI supplies placeholders for build |
| CI sets placeholder `DATABASE_URL` / `NEXT_PUBLIC_APP_URL` | Build needs the public URL; DB is not contacted during `next build` for Phase 0 |
| Manually add shadcn `Button` + `components.json` instead of interactive CLI | Non-interactive scaffold; same file layout shadcn expects |
| Pin exact dependency versions in `package.json` | SPEC section 2 requires pinning at build time |
| `.gitignore` ignores `.env*` locals but keeps `.env.example` tracked | Secrets stay local; template stays in repo |
| `typecheck` runs `next typegen` before `tsc` | Next 16 `next-env.d.ts` references `.next/types`; typegen makes CI typecheck work before build |
| Root layout uses `{ children: React.ReactNode }` instead of `LayoutProps` | Avoid depending on generated route types for a one-file layout |

## 2026-11-11 — Phase 1b scan pipeline

| Decision | Reason |
|---|---|
| Hand-wrote `drizzle/0001_anon_token_hash_step.sql` + snapshot/journal entries | `drizzle-kit generate` prompts interactively (rename vs create) and Windows PTY isn't available; drop+add chosen over rename so no raw token values could survive in `anon_token_hash` |
| `anon_token` dropped, `anon_token_hash` added (not renamed) | Old column could have held raw tokens; the hash column must only ever contain SHA-256 digests |
| Isomorphic `lib/scanner/validation.ts` + `validation.server.ts` that registers `validateTargetUrl` | The scan form (client component) needs the same Zod schema, but `url-validation.ts` uses `node:net` and cannot be bundled client-side. Server modules import `validation.server.ts`, which installs the strict check before use |
| `acceptedOwnership` is `z.boolean().refine(v => v === true)` instead of `z.literal(true)` | Identical runtime strictness (only boolean `true` passes) but keeps the form value type as `boolean`, avoiding casts in React Hook Form |
| Mode mismatched URLs are rejected, not ignored | `mode: "site"` with a repo URL filled in is almost certainly a user error; failing loudly beats silently scanning the wrong target |
| Repo URL regex: strict `https://github.com/<owner>/<repo>` with GitHub's owner charset, repo starting alphanumeric, optional `.git`/trailing slash | SPEC requires strict matching; full GitHub rules (reserved names, unicode) are approximated — documented as a heuristic |
| Per-domain rate limit keyed on site hostname, falling back to repo hostname (github.com) | "Same domain" most usefully means the target site; repo scans still count via the per-IP limit and github.com domain bucket |
| Inngest `scan.run` marks the scan `failed` then rethrows | Inngest retries transient failures; a retry can move the row back to `running`. Exhausted retries leave `failed` with a safe message |
| `scans.step` stores pipeline step ids (`validate-and-resolve`, `mark-running`, `finalize`); progress UI maps them onto the 6-item SPEC checklist | No real checks exist yet, so the mapping is approximate until Phase 2+ adds steps |
| `getEnv()` requires Upstash + Inngest keys only when `NODE_ENV=production`, exempting `phase-production-build` | CI builds without those secrets; runtime in production fails fast on misconfiguration while local dev stays key-free |
| Elapsed timer counts from page mount, not `created_at` | Simple and good enough for the skeleton; can be refined when the report UI lands |

## 2026-11-11 — Phase 1a SSRF-safe fetch

| Decision | Reason |
|---|---|
| Use Node `http`/`https` + custom `lookup`, not undici | Built-in; can pin the connect-time address after checking every DNS result |
| Request `Accept-Encoding: identity` only | Avoids gzip/br decompression bombs without extra stream complexity; size limit applies to bytes on the wire |
| Split `url-validation.ts` and `safe-fetch.ts` | Keeps pure URL/IP checks unit-testable without HTTP |
| Optional `lookup` / `checkIp` / `timeoutMs` / `maxBytes` / `connectPort` on `safeFetch` | Tests mock DNS and talk to an ephemeral loopback port while validated URLs stay on 80/443 |
| Read `NEXT_PUBLIC_APP_URL` directly in validation (not full `getEnv()`) | Unit tests should not require `DATABASE_URL`; app-host check only needs the public origin |
| Oversize bodies return `ok: true` with `truncated: true` | Matches the Phase 1a requirement to stream-cap and flag; `too_large` remains available for future hard-fail paths |

## 2026-11-12 — Scan progress checklist fix

| Decision | Reason |
|---|---|
| `lib/scanner/steps.ts` is the single source of truth for step ids, labels, and states | The UI previously hard-coded SPEC checklist labels for steps the pipeline never runs, so scans looked stuck; now Inngest writes `scans.step` and the UI renders exactly those steps |
| Only 4 steps exist (`queued`, `validate-and-resolve`, `mark-running`, `finalize`) | Mode-specific steps (`appliesTo: "site" | "repo"`) are supported by `stepsForMode` but none are added until the real checks land in Phases 2–3 |
| `onFailure` receives `{ event, step, error }` where `event.data.event` is the original triggering event | Verified against inngest 4.26.2 types (`FailureEventPayload`); the handler re-parses the nested event defensively and does nothing if it does not match |
| `NonRetriableError` for bad payload / missing scan / invalid stored URLs | These can never succeed on retry; transient errors keep Inngest's default retries and are only marked `failed` by `onFailure` after retries are exhausted |
| `scans.step` is kept (not cleared) when a scan fails | Lets the UI show which step failed; the progress page still shows the friendly failed screen for `status: "failed"` |
| GET `/api/scans/[id]` derives `mode` from stored URLs and returns `Cache-Control: no-store` | The UI needs the mode to render the right checklist; URLs, token hash, and error text are never exposed |
| `anonTokenHashEquals` returns false for empty inputs | An empty stored hash or cookie must never compare equal, even to another empty string |
| Elapsed timer computes from server `createdAt` | A page reload mid-scan no longer resets the `T+MM:SS` timer |

## 2026-11-13 — Phase 2A check framework, snapshot, persistence

| Decision | Reason |
|---|---|
| `RawFinding.evidence` is already redacted; persistence truncates it to 500 chars and `location` to 300 | SPEC 4.3 redaction rule; column caps keep rows small (AGENTS free-tier discipline) |
| Snapshot treats home-page HTTP status >= 400 as `site_unreachable` | `safeFetch` returns `ok: true` for HTTP errors; a scanner should not report on an error page |
| Snapshot notes become `info` findings with `checkId: "site.snapshot.notes"`, category `reliability` | SPEC requires skipped-fetch budgets to surface as info findings; reliability is the closest category for fetch-budget notes |
| Script discovery uses regex over `<script src>` and `<link rel="modulepreload">`, resolved against `finalUrl`, same-origin only, deduped, capped at 15 | SPEC 4.3 budgets; no HTML-parser dependency allowed |
| robots.txt disallows are checked per script path for `LaunchCheckBot`, with `*` groups as fallback and longest-match/allow-tie precedence | SPEC 7.4 + 4.3; missing/garbage robots.txt means allow all |
| Script fetches run at concurrency 4 with a shared deadline checked before each fetch; leftovers are counted once as skipped | SPEC 4.3 budgets; avoids double-counting when several workers hit the deadline |
| `persistFindings` uses a transaction only when the driver supports it; neon-http's `transaction()` exists but always throws "No transactions support", so it falls back to sequential delete+insert | SPEC requires idempotent persistence; delete-then-insert is already idempotent, the transaction is only an optimization where available |
| `runChecks` normalizes `finding.checkId` to the check's own id and converts throws/timeouts into a single `check_errored` info finding | SPEC 4.3: one bad check must never fail the scan |
| `maxDuration = 60` exported from `/api/inngest` | Inngest sync + snapshot/check work can exceed the default serverless limit; noted if the Next 16 build rejects the segment config |
| HSTS "weak" finding uses severity `low`, confidence `high` | Prompt's "low/high-confidence" read parallel to "medium/high-confidence" = severity/confidence pair; SPEC 4.1 lists hsts guidance as medium overall |
| Fixture server is plain HTTP, so scheme-dependent checks (HSTS) self-skip in fixture-server tests; HTTPS behavior is tested via a stub fetcher reporting an `https://` `finalUrl` | `safeFetch` cannot do TLS to the fixture server; stubbing `finalUrl` exercises the same check logic without real network |

## 2026-11-13 — Phase 2A follow-up: batch persist, snapshot budgets, retries

| Decision | Reason |
|---|---|
| `persistFindings` uses `db.batch([delete, insert])` (delete only when empty) instead of a transaction | drizzle-orm 0.44.5 neon-http supports `batch` (single HTTP round-trip); removes the transaction try/catch entirely |
| `location` stored as `origin + pathname` when it parses as a URL, else truncated to 300 | Query strings/fragments can carry tokens (`?token=...`) |
| `title` capped at 200 chars | Keeps finding rows small; titles are display strings |
| Script responses skipped when `finalUrl` origin differs from the page origin or content-type is image/video/audio/font | safeFetch follows redirects; off-origin or binary responses are not useful scan input |
| 25 MB total byte budget across HTML + script bodies, checked before each script fetch | SPEC 4.3 budget; shared counter may overshoot by one in-flight batch — accepted as a guard, not a hard cap |
| `retries: 2` on `scan.run` | Explicit cap instead of the SDK default; transient errors get two retries before `onFailure` marks the scan failed |

## 2026-11-14 — Phase 2B header, transport, and cookie checks

| Decision | Reason |
|---|---|
| `Check.timeoutMs` optional override; runner uses `check.timeoutMs ?? perCheckTimeoutMs` | site.https.redirect needs 12s for its extra probe; keeps the 5s default for everything else |
| CSP unsafe-inline is ignored when the same directive has a nonce/hash source or 'strict-dynamic'; 'unsafe-eval' always flags | Matches browser behavior — those tokens make browsers ignore unsafe-inline anyway |
| `site.headers.misc` flags a present-but-wrong X-Content-Type-Options value, not just a missing header | "nosniff" is the only useful value; anything else is equivalent to missing |
| `site.cookies` emits one finding per issue type listing at most 5 cookie NAMES; values never appear | SPEC 4.3 + prompt: cookie values are credentials-adjacent and must not be stored |
| HttpOnly split into sensitive-name (medium/medium) vs other (low/medium) findings | Prompt's two confidence/severity tiers for the same attribute |
| `site.https.redirect` fetch failures (blocked/timeout/refused/throw) produce no finding | Many hosts close port 80; a failed probe is not evidence of a problem |
| Fixture sites are plain HTTP, so `site.https.redirect` fires on both fixtures; clean-fixture assertions exclude it explicitly | HTTPS redirect behavior is covered by unit tests with crafted SafeFetchResult objects |

## 2026-11-14 — Phase 2C bundle secrets, backend detection, performance

| Decision | Reason |
|---|---|
| Secret patterns live in `lib/scanner/patterns/secrets.ts` with per-pattern `accept` filters | Shared with Phase 3 repo checks; AWS example key, placeholders, and low-entropy generic values are filtered after the regex match |
| Generic-assignment pattern uses a `(?<![A-Za-z0-9_.\-])` lookbehind and bounded quantifiers (name ≤128, value 24–256 chars) | Keeps the regex linear on pathological input; the ReDoS test scans ~2 MB in <1s |
| JWTs are NOT secret patterns; `findJwts`/`decodeJwtPayload` are separate helpers | SPEC: ordinary JWTs are handled by the Supabase check, not flagged as generic secrets |
| `site.bundle.secrets` budget is 10M UTF-16 code units (not bytes), HTML first then scripts in order, partial scan of the boundary script | "10 MB of text" has no exact byte definition for strings; code units are a cheap, predictable proxy and offsets stay valid |
| Secret evidence is `<pattern name>: <redactSecret(value)> at character <index>`; location is origin+pathname of the script (or page for HTML) | SPEC 2C evidence rules; query strings/fragments can carry tokens |
| High-confidence secret titles drop "Possible" (`X found in public code`); lower confidence uses `Possible X found in public code` | Prompt: "use 'possible' wording when confidence is not high" |
| `site.backend.supabase` emits the critical service_role finding independently of the anon info finding; both can fire together | SPEC treats them as separate signals; service_role is critical wherever it appears |
| Supabase/Firebase detection never makes network calls; JWT payloads are decoded without verification | SPEC 4.1/4.3: detection only, RLS/Rules cannot be verified externally |
| Firebase fires on firebaseapp.com / firebaseio.com / firebasestorage hosts OR a projectId+AIza-apiKey pair in the same text; apiKey never appears in evidence | An AIza key alone is a Google Maps/browser key (public by design) — the clean fixture relies on this |
| `site.perf.basic` counts an `<img>` as missing dimensions only when BOTH width and height are absent, needs ≥5 to fire | Prompt's literal "neither width nor height"; conservative to avoid noise |
| Script-size finding is replaced by an info note when any script is truncated or snapshot notes record skips | Sizes would be lower bounds; SPEC requires noting skipped text instead of reporting a misleading number |
| `persistFindings` scrubs title/evidence/location via `scrubSecrets` AFTER truncation and location sanitizing | SPEC 2C: defensive scrub so a buggy check can never persist a full secret |
| Fixture secrets/JWTs/apiKeys are assembled at runtime via string concatenation and base64url helpers | No secret-shaped literal may exist in the repo; the served bundle still contains the assembled values |

## 2026-11-23 — Phase 3A repo snapshot, repo checks, pipeline step

| Decision | Reason |
|---|---|
| `@octokit/rest` was already pinned at 22.0.1 before this phase | Dependency landed with an earlier docs/dependency commit; verified installed and `pnpm build`-compatible |
| Octokit timeout via per-request `request: { signal: AbortSignal.timeout(10_000) }` | Octokit 22 supports `signal` in `RequestRequestOptions`; no global timeout option exists |
| User agent `LaunchCheckBot/1.0` on the Octokit client (not the safeFetch UA) | SPEC 4.3 names this UA for repo metadata calls; file contents still go through safeFetch's own UA |
| Private repos map to `repo_not_found` | SPEC: v1 scans public repos only; a private repo must be indistinguishable from a missing one |
| Rate limit = 403/429 AND (`x-ratelimit-remaining: 0` OR message matches /rate limit/i) | Covers both primary and secondary GitHub rate limits without flagging ordinary 403s |
| Error messages are fixed generic strings; response bodies and the token never appear | SPEC 4.3 + AGENTS: no secrets or internals in errors |
| `parseRepoUrl` reuses the exported `GITHUB_REPO_URL` regex (capture groups added) and strips a trailing `.git` | Single source of truth for repo URL rules; the greedy repo group would otherwise swallow ".git" |
| `snapshot.tree` keeps every blob (including skipped/oversized files); `files` holds only fetched text | Checks like `repo.env.committed` and `repo.quality.basics` need the full listing, not just fetched contents |
| Oversized tree entries (>200 KB) are skipped before fetching; fetched bodies are also hard-truncated to 200 KB | SPEC 4.3 per-file cap; the injected fetcher is NOT modified (its cap stays 5 MB) |
| Fetch order: env/config tier, then app/src/pages/lib/api/supabase, then rest; shallow before deep, alpha tiebreak | SPEC 4.3/Phase 3A priority; deterministic so tests can assert exact order |
| Byte budget counts post-truncation body length; concurrency overshoot bounded by 6 in-flight fetches | Same guard-rail approach as the site snapshot (documented there as acceptable) |
| `runChecks` generalized to `<Ctx, C extends RunnableCheck<Ctx>>`; `Check.target` narrowed to `"site"`, new `RepoCheck.target: "repo"` | Site and repo checks share one runner; `target` was never read at runtime |
| `persistFindings` takes required `{ scope }` and deletes `check_id LIKE '<scope>.%'` for this scan only | SPEC 4.3 scoped persistence; `site.`/`repo.` prefixes match every check id by convention |
| `repo.env.committed`: critical/high only when a fetched env file has a non-empty `KEY=value`; otherwise high/medium | SPEC gives severity guidance only; confidence medium when contents are unknown or placeholder-like |
| `repo.secrets.patterns` sorts candidates by severity before the 20-finding cap | A repo full of test fixtures must not crowd out a real critical leak |
| `.env.example` files are exempt from the test-path down-rank | SPEC 4.3: a real-looking key in an example file is a genuine leak |
| `service_role` JWTs are flagged by decoding the payload (no verification) and checking `role` | Same detection approach as `site.backend.supabase`; signature verification is impossible and unnecessary for a heuristic |
| `repo.quality.basics` "workspace root" = any directory containing a `package.json`; test detection accepts `*.test.*`/`*.spec.*`, `__tests__`/`tests` dir segments, or a `"test"` script key inside `scripts` | Simplest reading of SPEC 4.2 `repo.quality.basics`; documented as a heuristic |
| Repo-only scan with unreadable repo throws `NonRetriableError("repo_unreachable")` regardless of the specific reason | SPEC section 10 implemented-pipeline note says exactly this |
| `GITHUB_TOKEN` read via `getEnv()` inside the scan-repo step; optional everywhere | SPEC 16: optional, raises GitHub rate limits; absent token still scans public repos |

## 2026-11-25 — Rate-limit UX, per-repo buckets, and scan de-duplication

| Decision | Reason |
|---|---|
| Per-target bucket key is the site hostname or `github.com/<owner>/<repo>` lowercased — never bare `github.com` | The old key put every repo scan in one global daily bucket shared by all users |
| Limits are env-driven: `RATE_LIMIT_IP_PER_HOUR` (default 10 production / 100 otherwise) and `RATE_LIMIT_DOMAIN_PER_DAY` (default 10), integers 1–100 via Zod | SPEC 7.2 abuse controls need tuning without code changes; invalid values fall back to defaults |
| All buckets are peeked before any token is consumed (Upstash `getRemaining`, in-memory `peek`) | A rejected request must not consume quota from the other bucket; @upstash/ratelimit 2.2.0 supports non-consuming `getRemaining` |
| A consume that still fails after a passing peek (concurrent race) reports the rejection | Peek+consume is not atomic; the race window is tiny and the outcome stays safe (request rejected, never over-admitted) |
| When several buckets reject, the one with the longer `retryAfterSeconds` is reported | SPEC asks for a single calm, specific message; the longest wait is the honest answer |
| POST order is validate → de-dupe → rate-limit → insert | Invalid bodies never touch the limiter; de-duped resubmits reuse the scan and consume no token |
| De-dup window: same anon token hash + same stored siteUrl/repoUrl pair, status queued/running, or completed within 60 s → 200 `{ id, reused: true }` | Covers double-clicks and retries without masking genuinely new scans; failed scans are never reused |
| Mode is implied by which URL columns are set (there is no mode column) | The (siteUrl, repoUrl) pair uniquely determines the mode for all valid requests |
| 429 body is `{ error: "rate_limited", scope, retryAfterSeconds, message }` with `Retry-After` + `Cache-Control: no-store`; 503 adds `Retry-After: 30` | Lets the UI show an exact countdown; no-store prevents cached error pages |
| UI countdown disables submit until zero, announces politely only on minute changes, and never touches form values | Accessibility: `role="alert"` announces once; the per-second tick is `aria-live="off"` |

## 2026-11-26 — Phase 3B repo checks (OSV audit + pattern heuristics)

| Decision | Reason |
|---|---|
| OSV uses a dedicated fixed-host client (`api.osv.dev`) instead of the GET-only injected `Fetcher` | The batch query needs POST; the host is a constant so it is not an SSRF path (SPEC 4.3) |
| `repo.deps.audit` picks ONE root lockfile (package-lock > pnpm-lock > yarn.lock), caps at 1500 packages / 50 advisory lookups, and degrades every failure to an info finding | SPEC 4.3 limits; the check must never throw or block the scan |
| `repo.stripe.webhook`, `repo.api.noauth`, `repo.supabase.rls` are pure heuristics over fetched files — every finding says "possible" and confidence drops on ambiguous signals (local verify module, middleware, truncated/missing SQL) | SPEC 4.3: passive checks report potential issues only |
| SQL files are not path-filtered in `repo.supabase.rls` | A `tests/`-style path filter would also skip real migrations like `20240101_sample_data.sql`; a possible follow-up is skipping only a `tests/` or `supabase/tests/` directory |
- A backtick inside a `String.raw` template literal ends the literal; write it as `\x60` in regex character classes.
