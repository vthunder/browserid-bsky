#!/usr/bin/env node
// Publish-state oracle for this repo's npm packages (@browserid-ng/bsky).
// Adapted from browserid-ng scripts/publish-status.mjs (bean 1bqx).
//
// "What needs publishing" must be a derived fact, not knowledge someone holds:
// on 2026-08-26 two packages' shipped code changed without a version bump, a
// publish loop silently no-op'd on them (the registry already had those
// versions — with the OLD code), and nobody could tell without hand-diffing
// npm. This script makes the state deterministic. For every publishable
// package it reports one of:
//
//   OK             local version is published and its content matches the
//                  registry tarball byte-for-byte
//   NEEDS PUBLISH  local version is not on the registry (publish it)
//   NEEDS BUMP     local version IS on the registry but the content differs —
//                  the drift that motivated this script; bump before publish
//   BEHIND         registry latest is newer than the local version (the repo
//                  is stale, or someone published from elsewhere)
//   ERROR          registry unreachable / tooling missing (never guessed)
//
// Usage:
//   node scripts/publish-status.mjs             table; exit 1 on NEEDS BUMP
//   node scripts/publish-status.mjs --json      machine-readable, same exit
//   node scripts/publish-status.mjs --strict    also exit 1 on ERROR/BEHIND
//   node scripts/publish-status.mjs --publish   npm-publish every NEEDS
//                                               PUBLISH npm package (adds
//                                               --provenance in CI); the
//                                               python package is published
//                                               by CI's pypi job, never here
//
// Zero dependencies; needs `npm` and `tar` on PATH (`uv` for the python
// package's drift check — without it that check degrades to version-only).

import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const repoRoot = join(import.meta.dirname, "..");
const packageDirs = ["agent-cli"]; // npm packages in this repo (dir relative to root)
const args = new Set(process.argv.slice(2));

function sh(cmd, cmdArgs, opts = {}) {
  return execFileSync(cmd, cmdArgs, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...opts });
}

function haveCmd(cmd) {
  try {
    sh(cmd, ["--version"]);
    return true;
  } catch {
    return false;
  }
}

// Extract a gzipped tarball and return the diff -r output vs another tree
// ("" = identical). PKG-INFO is generated sdist metadata, not source.
function diffTarballs(aTar, bTar, work) {
  const a = join(work, "a");
  const b = join(work, "b");
  for (const [dir, tarball] of [[a, aTar], [b, bTar]]) {
    sh("mkdir", ["-p", dir]);
    sh("tar", ["-xzf", tarball, "-C", dir]);
  }
  try {
    sh("diff", ["-r", "--exclude=PKG-INFO", a, b]);
    return "";
  } catch (e) {
    return (e.stdout || "content differs").toString();
  }
}

async function fetchToFile(url, dest) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`GET ${url}: ${res.status}`);
  writeFileSync(dest, Buffer.from(await res.arrayBuffer()));
}

// --- package discovery -----------------------------------------------------

function npmPackages() {
  const pkgs = [];
  for (const entry of packageDirs) {
    const manifest = join(repoRoot, entry, "package.json");
    let pkg;
    try {
      pkg = JSON.parse(readFileSync(manifest, "utf8"));
    } catch {
      continue;
    }
    if (pkg.private) continue;
    pkgs.push({ kind: "npm", dir: join(repoRoot, entry), rel: entry, name: pkg.name, version: pkg.version });
  }
  return pkgs;
}

function pythonPackages() {
  return []; // no PyPI packages in this repo
}

// --- per-registry checks ---------------------------------------------------

async function checkNpm(pkg, work) {
  const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkg.name).replace("%2F", "/")}`);
  if (res.status === 404) return { status: "NEEDS PUBLISH", detail: "package not on npm at all" };
  if (!res.ok) return { status: "ERROR", detail: `registry ${res.status}` };
  const meta = await res.json();
  const latest = meta["dist-tags"]?.latest;
  const published = meta.versions?.[pkg.version];

  if (!published) {
    return { status: "NEEDS PUBLISH", detail: `local ${pkg.version}, npm latest ${latest ?? "none"}` };
  }

  // Same version on both sides — the only honest check is content.
  const packed = JSON.parse(sh("npm", ["pack", "--json", "--pack-destination", work], { cwd: pkg.dir }));
  const localTar = join(work, packed[0].filename);
  const remoteTar = join(work, "registry.tgz");
  await fetchToFile(published.dist.tarball, remoteTar);
  const diff = diffTarballs(localTar, remoteTar, join(work, "cmp"));
  if (diff === "") {
    return latest === pkg.version
      ? { status: "OK", detail: `${pkg.version} published, content matches` }
      : { status: "BEHIND", detail: `local ${pkg.version} matches its publish, but npm latest is ${latest}` };
  }
  const files = [
    ...new Set(
      diff
        .split("\n")
        .filter((l) => l.startsWith("diff ") || l.startsWith("Only in "))
        .map((l) =>
          l.startsWith("Only in ")
            ? l.replace(/^Only in .*?: /, "") + " (one side only)"
            : l.split(" ").pop().replace(/^.*\/package\//, "")
        )
    ),
  ];
  return { status: "NEEDS BUMP", detail: `content drift at ${pkg.version}: ${files.slice(0, 5).join(", ")}${files.length > 5 ? " …" : ""}` };
}

async function checkPypi(pkg, work) {
  const res = await fetch(`https://pypi.org/pypi/${pkg.name}/json`);
  if (res.status === 404) return { status: "NEEDS PUBLISH", detail: "package not on PyPI at all" };
  if (!res.ok) return { status: "ERROR", detail: `PyPI ${res.status}` };
  const meta = await res.json();
  const latest = meta.info?.version;
  const files = meta.releases?.[pkg.version];

  if (!files || files.length === 0) {
    return { status: "NEEDS PUBLISH", detail: `local ${pkg.version}, PyPI latest ${latest ?? "none"}` };
  }

  const sdist = files.find((f) => f.packagetype === "sdist");
  if (!sdist) return { status: "ERROR", detail: `no sdist on PyPI for ${pkg.version}` };
  if (!haveCmd("uv")) {
    return { status: latest === pkg.version ? "OK" : "BEHIND", detail: `${pkg.version} published (uv missing — drift not checked)` };
  }
  sh("uv", ["build", "--sdist", "--out-dir", work], { cwd: pkg.dir });
  const localTar = join(work, `${pkg.name.replace(/-/g, "_")}-${pkg.version}.tar.gz`);
  const remoteTar = join(work, "pypi.tar.gz");
  await fetchToFile(sdist.url, remoteTar);
  const diff = diffTarballs(localTar, remoteTar, join(work, "cmp"));
  if (diff === "") {
    return latest === pkg.version
      ? { status: "OK", detail: `${pkg.version} published, content matches` }
      : { status: "BEHIND", detail: `local ${pkg.version} matches its publish, but PyPI latest is ${latest}` };
  }
  return { status: "NEEDS BUMP", detail: `content drift at ${pkg.version}` };
}

// --- main ------------------------------------------------------------------

const packages = [...npmPackages(), ...pythonPackages()];
const rows = [];
for (const pkg of packages) {
  const work = mkdtempSync(join(tmpdir(), "pubstat-"));
  let result;
  try {
    result = pkg.kind === "npm" ? await checkNpm(pkg, work) : await checkPypi(pkg, work);
  } catch (e) {
    result = { status: "ERROR", detail: String(e.message ?? e).split("\n")[0] };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
  rows.push({ ...pkg, ...result });
}

if (args.has("--publish")) {
  for (const row of rows) {
    if (row.status !== "NEEDS PUBLISH" || row.kind !== "npm") continue;
    const publishArgs = ["publish", "--access", "public"];
    if (process.env.CI) publishArgs.push("--provenance");
    console.log(`publishing ${row.name}@${row.version} …`);
    execFileSync("npm", publishArgs, { cwd: row.dir, stdio: "inherit" });
    row.status = "PUBLISHED";
    row.detail = `published ${row.version}`;
  }
}

if (args.has("--json")) {
  console.log(JSON.stringify(rows.map(({ dir, ...r }) => r), null, 2));
} else {
  const w1 = Math.max(...rows.map((r) => r.rel.length));
  const w2 = Math.max(...rows.map((r) => r.name.length));
  const w3 = Math.max(...rows.map((r) => r.status.length));
  for (const r of rows) {
    console.log(`${r.rel.padEnd(w1)}  ${r.name.padEnd(w2)}  ${r.version.padEnd(7)}  ${r.status.padEnd(w3)}  ${r.detail}`);
  }
}

const bad = rows.filter((r) => r.status === "NEEDS BUMP");
const iffy = rows.filter((r) => r.status === "ERROR" || r.status === "BEHIND");
if (bad.length > 0) process.exit(1);
if (args.has("--strict") && iffy.length > 0) process.exit(1);
