#!/usr/bin/env bash
# The fast local loop for what .github/workflows/release-candidate.yml checks
# on the staging mirror (sandmill-infra/ip-approval/PLAN.md). The mirror run,
# not this script, qualifies a commit for submission. Runs every step, prints
# one line per step, and exits non-zero if any step failed or the run left
# the tree dirty.
#
#   make release-check                                  # clean tree, repo root
#   RELEASE_CHECK_SKIP="supply-chain" make release-check   # space-separated step names (dev only)
#
# On the dev box run it through `ssh localtest` so cargo's test binaries are
# not stalled by Gatekeeper. Needs: rustup, node/npm, cargo-audit, gitleaks;
# docker for the image step (skipped, and said so, without it). Unlike CI,
# the tests here are not network-isolated (that needs Linux namespaces).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
export PATH="$HOME/.cargo/bin:$PATH"
LOGDIR="${RELEASE_CHECK_LOGDIR:-/tmp/release-check-bsky}"
mkdir -p "$LOGDIR"
SKIP=" ${RELEASE_CHECK_SKIP:-} "
declare -a RESULTS=()
FAILED=0

step() {
  local name="$1"; shift
  if [[ "$SKIP" == *" $name "* ]]; then RESULTS+=("skip  $name (RELEASE_CHECK_SKIP)"); return 0; fi
  local log="$LOGDIR/$name.log"
  printf '==> %s\n' "$name"
  if "$@" >"$log" 2>&1; then
    RESULTS+=("ok    $name")
  else
    RESULTS+=("FAIL  $name  (log: $log)")
    FAILED=1
    tail -40 "$log" | sed 's/\x1b\[[0-9;]*m//g'
  fi
}

# The exact rustc the image builds with: the Dockerfile builder tag
# (rust:X.Y.Z-…@sha256:…), which CI also pins and checks against the digest.
pinned_toolchain() {
  sed -nE 's/^FROM rust:([0-9]+\.[0-9]+\.[0-9]+)-[^@ ]+@sha256:[0-9a-f]{64} AS builder.*/\1/p' Dockerfile
}
toolchain_pins() {
  local v; v="$(pinned_toolchain)"
  [ -n "$v" ] || { echo "Dockerfile builder is not rust:X.Y.Z-<distro>@sha256:<digest>"; return 1; }
  local n; n="$(grep -c "dtolnay/rust-toolchain@[0-9a-f]\{40\} # $v\$" .github/workflows/release-candidate.yml)"
  local all; all="$(grep -c 'dtolnay/rust-toolchain@' .github/workflows/release-candidate.yml)"
  [ "$n" -gt 0 ] && [ "$n" = "$all" ] || { echo "release-candidate.yml pins a toolchain other than the Dockerfile's $v"; return 1; }
  echo "Dockerfile and CI both pin rust $v"
}
rust_workspace() {
  local v; v="$(pinned_toolchain)"
  rustup toolchain install "$v" --profile minimal >/dev/null 2>&1 || { echo "rustup could not install $v"; return 1; }
  echo "testing with rust $v"
  cargo "+$v" test --workspace --locked
}
# What publish.yml fails on: a version already on npm with other content.
publish_drift() { node scripts/publish-status.mjs; }
agent_cli() { (cd agent-cli && npm ci --ignore-scripts --no-audit --no-fund && node --test); }
supply_chain() { scripts/supply-chain-audit.sh all; }
# The deploy image plus the CI smoke test (stub localhost broker, health probe).
image() {
  docker build --platform linux/amd64 -f Dockerfile -t rc-pds-bridge . || return 1
  local stub; stub="$(cd .github/rc/stub-broker && python3 -m http.server 18081 --bind 127.0.0.1 >/dev/null 2>&1 & echo $!)"
  docker rm -f rc-pds-bridge-smoke >/dev/null 2>&1
  docker run -d --name rc-pds-bridge-smoke --network host -e BRIDGE_PORT=18080 -e BROKER_URL=http://127.0.0.1:18081 \
    -e PDS_URL=http://127.0.0.1:1 -e PDS_ADMIN_PASSWORD=rc-throwaway rc-pds-bridge >/dev/null
  local i rc=1
  for i in $(seq 1 60); do
    [ "$(curl -sf http://127.0.0.1:18080/browserid/health)" = ok ] && { rc=0; break; }
    sleep 1
  done
  [ $rc = 0 ] || docker logs rc-pds-bridge-smoke
  docker rm -f rc-pds-bridge-smoke >/dev/null 2>&1; kill "$stub" 2>/dev/null
  return $rc
}

# First, before any step can write into the tree.
step publish-drift  publish_drift
step toolchain-pins toolchain_pins
step rust-workspace rust_workspace
step agent-cli      agent_cli
step supply-chain   supply_chain
if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  step image image
else
  RESULTS+=("skip  image (no docker here; rc / image pds-bridge runs it on the mirror)")
fi

echo
echo "release-check summary ($(git rev-parse --short HEAD)):"
printf '  %s\n' "${RESULTS[@]}"
if [ -z "$(git status --porcelain)" ]; then
  echo "  tree clean after the run"
else
  echo "  FAIL  the run left the tree dirty:"; git status --short | sed 's/^/    /'; FAILED=1
fi
exit $FAILED
