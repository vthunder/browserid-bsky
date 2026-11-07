#!/usr/bin/env bash
# Dependency + secrets audit, the same gate locally and in CI (adapted from
# browserid-ng scripts/supply-chain-audit.sh). Usage:
#
#   scripts/supply-chain-audit.sh [rust|node|secrets|all]   (default all)
#
# Policy (one place, so CI and release-check cannot drift):
#   rust    `cargo audit` fails on any RUSTSEC vulnerability not ignored in
#           .cargo/audit.toml (warnings for unsound/unmaintained/yanked are
#           printed, not fatal).
#   node    `npm audit --omit=dev` on agent-cli (its lockfile); HIGH or
#           CRITICAL in production deps fails unless the GHSA id is listed in
#           .github/supply-chain/npm-ignore.txt.
#   secrets `gitleaks git` over the full history (default rules).
#
# Tools: cargo-audit (`cargo install cargo-audit --locked`), npm, gitleaks.
# A missing tool fails the matching section rather than silently passing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
MODE="${1:-all}"
FAIL=0

# ids from an ignore file: first token of every non-comment, non-empty line.
ids_from() { grep -vE '^\s*(#|$)' "$1" 2>/dev/null | awk '{print $1}' || true; }

section() { printf '\n==> %s\n' "$*"; }

run_rust() {
  section "cargo audit"
  command -v cargo-audit >/dev/null || { echo "cargo-audit not installed"; return 1; }
  cargo audit
}

NODE_PACKAGES=(agent-cli)

run_node() {
  command -v npm >/dev/null || { echo "npm not installed"; return 1; }
  local ignore; ignore="$(ids_from .github/supply-chain/npm-ignore.txt | tr '\n' ' ')"
  local pkg rc
  for pkg in "${NODE_PACKAGES[@]}"; do
    section "npm audit: $pkg"
    [ -f "$pkg/package-lock.json" ] || { echo "$pkg has no package-lock.json"; FAIL=1; continue; }
    rc=0
    (cd "$pkg" && { npm audit --omit=dev --json 2>/dev/null || true; } \
      | NPM_IGNORE="$ignore" node -e '
        let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{
          let r; try{ r=JSON.parse(s);}catch{ console.log("npm audit produced no JSON (registry unreachable?)"); process.exit(2);}
          if (r.error) { console.log("npm audit error: "+JSON.stringify(r.error)); process.exit(2); }
          const ignore=new Set((process.env.NPM_IGNORE||"").split(/\s+/).filter(Boolean));
          const vulns=r.vulnerabilities||{}; let bad=0, shown=0;
          for (const [name,v] of Object.entries(vulns)) {
            const direct=(v.via||[]).filter(x=>typeof x==="object");
            if (!direct.length) continue;            // transitive marker only
            const ids=direct.map(x=>x.url?x.url.split("/").pop():x.source);
            shown++;
            const gate=(v.severity==="high"||v.severity==="critical");
            const ignored=ids.length&&ids.every(i=>ignore.has(i));
            console.log(`${gate&&!ignored?"FAIL":"    "} ${v.severity.padEnd(8)} ${name}@${v.range}  ${ids.join(",")}${ignored?"  (ignored)":""}`);
            if (gate&&!ignored) bad++;
          }
          if (!shown) console.log("found 0 vulnerabilities");
          process.exit(bad?1:0);
        });') || rc=$?
    [ "$rc" -eq 0 ] || FAIL=1
  done
  return $FAIL
}

run_secrets() {
  section "gitleaks (full history)"
  command -v gitleaks >/dev/null || { echo "gitleaks not installed"; return 1; }
  gitleaks git --no-banner --redact=90 .
}

case "$MODE" in
  rust)    run_rust ;;
  node)    run_node ;;
  secrets) run_secrets ;;
  all)
    run_rust    || FAIL=1
    run_node    || FAIL=1
    run_secrets || FAIL=1
    ;;
  *) echo "usage: $0 [rust|node|secrets|all]" >&2; exit 2 ;;
esac
exit $FAIL
