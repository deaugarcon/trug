#!/bin/bash
# Usage: ./Scripts/dev.sh build|test|run [args...]
#
# NOTE: there is NO real `lint` subcommand here. `dev.sh <cmd>` execs `swift <cmd>`,
# so `dev.sh lint` becomes `swift lint` — an unknown subcommand that prints
# "unable to invoke subcommand: swift-lint" to stderr but STILL EXITS 0 (a
# false-green). Do NOT cite `dev.sh lint` as lint evidence — it runs nothing.
# The real lint gate is `./Scripts/lint-no-ui-imports.sh` (the no-UI-imports guard).
# Wiring a style linter is a separate, deliberately-deferred change.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if command -v brew &>/dev/null; then
  _OPENSSL_PC="$(brew --prefix openssl@3)/lib/pkgconfig"
else
  _OPENSSL_PC=""
fi
export PKG_CONFIG_PATH="$ROOT/Vendor/lib/pkgconfig${_OPENSSL_PC:+:$_OPENSSL_PC}${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
# Use Xcode toolchain when available so Swift Testing + Foundation overlay resolves correctly.
if [ -z "${DEVELOPER_DIR:-}" ] && [ -d "/Applications/Xcode-beta.app/Contents/Developer" ]; then
    export DEVELOPER_DIR="/Applications/Xcode-beta.app/Contents/Developer"
fi
CMD="${1:?usage: dev.sh build|test|run [args...]}"; shift
exec swift "$CMD" --package-path "$ROOT" "$@"
