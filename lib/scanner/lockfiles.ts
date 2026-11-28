/**
 * Lockfile parsing for the repo dependency audit (Phase 3B). Pure functions,
 * no I/O, never throws. Supports package-lock.json (v1 nested dependencies and
 * v2/v3 "packages" map), pnpm-lock.yaml (plain-text parsing, no YAML dep),
 * and yarn.lock v1. Yarn Berry (__metadata) and anything else is "unsupported".
 */

export type LockfilePackage = { name: string; version: string };

export type LockfileParseResult =
  | { ok: true; packages: LockfilePackage[] }
  | { ok: false; reason: "unsupported" | "unparseable" };

const SEMVER_RE = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

function isSemver(version: string): boolean {
  return SEMVER_RE.test(version);
}

function basename(path: string): string {
  const index = path.lastIndexOf("/");
  return index === -1 ? path : path.slice(index + 1);
}

function pushPackage(
  packages: LockfilePackage[],
  seen: Set<string>,
  name: string,
  version: string,
): void {
  if (!name || !isSemver(version)) {
    return;
  }
  const key = `${name}@${version}`;
  if (!seen.has(key)) {
    seen.add(key);
    packages.push({ name, version });
  }
}

function unsupported(): LockfileParseResult {
  return { ok: false, reason: "unsupported" };
}
function unparseable(): LockfileParseResult {
  return { ok: false, reason: "unparseable" };
}

// ---------- package-lock.json ----------

type NpmLock = {
  dependencies?: Record<string, NpmDependency>;
  packages?: Record<string, { version?: string; link?: boolean }>;
};
type NpmDependency = {
  version?: string;
  dependencies?: Record<string, NpmDependency>;
};

function collectNpmV1(
  deps: Record<string, NpmDependency> | undefined,
  packages: LockfilePackage[],
  seen: Set<string>,
): void {
  for (const [name, dep] of Object.entries(deps ?? {})) {
    if (typeof dep.version === "string") {
      pushPackage(packages, seen, name, dep.version);
    }
    collectNpmV1(dep.dependencies, packages, seen);
  }
}

function parsePackageLock(text: string): LockfileParseResult {
  let data: NpmLock;
  try {
    data = JSON.parse(text) as NpmLock;
  } catch {
    return unparseable();
  }
  if (typeof data !== "object" || data === null) {
    return unparseable();
  }

  const packages: LockfilePackage[] = [];
  const seen = new Set<string>();

  if (data.packages && typeof data.packages === "object") {
    // v2/v3: keys like "node_modules/a" or "node_modules/a/node_modules/b".
    for (const [key, entry] of Object.entries(data.packages)) {
      if (key === "" || entry.link === true || typeof entry.version !== "string") {
        continue;
      }
      const marker = "node_modules/";
      const index = key.lastIndexOf(marker);
      if (index === -1) {
        continue;
      }
      const name = key.slice(index + marker.length);
      pushPackage(packages, seen, name, entry.version);
    }
    return { ok: true, packages };
  }

  collectNpmV1(data.dependencies, packages, seen);
  return { ok: true, packages };
}

// ---------- pnpm-lock.yaml (text parsing only) ----------

/** Extract "name" and "version" from a pnpm packages: key. */
function parsePnpmKey(rawKey: string): { name: string; version: string } | null {
  let key = rawKey.trim().replace(/^['"]|['"]$/g, "");
  // Strip peer-dependency suffixes: name@1.2.3(react@18.2.0) -> name@1.2.3
  key = key.replace(/\s*\([^()]*\)\s*$/, "");
  // Older style prefixes the key with "/".
  key = key.replace(/^\/+/, "");
  if (key === "") {
    return null;
  }

  // "name@version" or "@scope/name@version" — split at the LAST '@'.
  const at = key.lastIndexOf("@");
  if (at > 0) {
    const name = key.slice(0, at);
    const version = key.slice(at + 1);
    return { name, version };
  }
  // Older "/name/version" style after the leading slash was stripped.
  const slash = key.lastIndexOf("/");
  if (slash > 0) {
    return { name: key.slice(0, slash), version: key.slice(slash + 1) };
  }
  return null;
}

function parsePnpmLock(text: string): LockfileParseResult {
  if (!/^lockfileVersion:/m.test(text)) {
    return unparseable();
  }
  const lines = text.split("\n");
  const packagesStart = lines.findIndex((line) => /^packages:\s*$/.test(line));
  if (packagesStart === -1) {
    // A valid lockfile with no packages section yet.
    return { ok: true, packages: [] };
  }

  const packages: LockfilePackage[] = [];
  const seen = new Set<string>();
  for (let i = packagesStart + 1; i < lines.length; i++) {
    const line = lines[i];
    // The packages section ends at the next top-level (unindented) key.
    if (/^[^\s#]/.test(line)) {
      break;
    }
    const match = /^\s{2,}['"]?([^'"]+?)['"]?:\s*(?:\{|$)/.exec(line);
    if (!match?.[1]) {
      continue;
    }
    const parsed = parsePnpmKey(match[1]);
    if (parsed) {
      pushPackage(packages, seen, parsed.name, parsed.version);
    }
  }
  return { ok: true, packages };
}

// ---------- yarn.lock v1 ----------

function yarnNameFromDescriptor(descriptor: string): string | null {
  const cleaned = descriptor.trim().replace(/^['"]|['"]$/g, "");
  if (cleaned === "") {
    return null;
  }
  // "name@range" or "@scope/name@range"; a bare "name" has no '@' at pos > 0.
  const at = cleaned.lastIndexOf("@");
  if (at <= 0) {
    return cleaned.includes("/") ? null : cleaned;
  }
  return cleaned.slice(0, at);
}

function parseYarnLock(text: string): LockfileParseResult {
  if (/^__metadata:/m.test(text)) {
    return unsupported(); // Yarn Berry
  }
  const lines = text.split("\n");
  const packages: LockfilePackage[] = [];
  const seen = new Set<string>();
  let currentNames: string[] = [];

  const flush = () => {
    currentNames = [];
  };

  for (const line of lines) {
    if (line !== "" && !/^\s/.test(line)) {
      // A new block header: "name@range, name@range:" possibly quoted.
      flush();
      if (line.trimEnd().endsWith(":")) {
        const header = line.trim().slice(0, -1);
        for (const descriptor of header.split(/","|",\s*|",\s+/)) {
          const name = yarnNameFromDescriptor(descriptor);
          if (name && !currentNames.includes(name)) {
            currentNames.push(name);
          }
        }
      }
      continue;
    }
    const versionMatch = /^\s+version\s+"([^"]+)"\s*$/.exec(line);
    if (versionMatch?.[1]) {
      for (const name of currentNames) {
        pushPackage(packages, seen, name, versionMatch[1]);
      }
    }
  }
  if (packages.length === 0 && !lines.some((l) => /^\s+version\s+"/.test(l))) {
    return unparseable();
  }
  return { ok: true, packages };
}

/**
 * Parse a lockfile by filename. `name` may be a path; only the basename
 * matters. Never throws.
 */
export function parseLockfile(name: string, text: string): LockfileParseResult {
  try {
    const base = basename(name).toLowerCase();
    if (base === "package-lock.json") {
      return parsePackageLock(text);
    }
    if (base === "pnpm-lock.yaml") {
      return parsePnpmLock(text);
    }
    if (base === "yarn.lock") {
      return parseYarnLock(text);
    }
    return unsupported();
  } catch {
    return unparseable();
  }
}
