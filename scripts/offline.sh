#!/usr/bin/env bash
# Run a command with no network except loopback, as the current user.
# Linux with passwordless sudo only (the CI runners): a fresh network
# namespace has no route anywhere, so a test that reaches for Bluesky, a DNS
# resolver or any third-party API fails instead of passing by luck.
#
#   scripts/offline.sh cargo test --workspace --locked --offline
set -euo pipefail
[ "$(uname -s)" = Linux ] || { echo "offline.sh: Linux only" >&2; exit 2; }
exec sudo -E env PATH="$PATH" HOME="$HOME" unshare --net -- \
  bash -c 'ip link set lo up && exec setpriv --reuid="$0" --regid="$1" --init-groups -- "${@:2}"' \
  "$(id -u)" "$(id -g)" "$@"
