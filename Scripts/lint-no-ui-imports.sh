#!/bin/bash
# Spec design rule 2: Core packages may not import AppKit/SwiftUI.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIRS=()
[ -d "$ROOT/Sources/CWrappers" ] && DIRS+=("$ROOT/Sources/CWrappers")
[ -d "$ROOT/Sources/DeviceCore" ] && DIRS+=("$ROOT/Sources/DeviceCore")
[ -d "$ROOT/Sources/BackupCore" ] && DIRS+=("$ROOT/Sources/BackupCore")
if [ ${#DIRS[@]} -eq 0 ]; then
  echo "FAIL: no Core source dirs found — repo layout changed? Update this script." >&2; exit 1
fi
if grep -rnE '^\s*import (AppKit|SwiftUI)\b' "${DIRS[@]}" 2>/dev/null; then
  echo "FAIL: UI import found in Core package" >&2; exit 1
fi
echo "OK: no UI imports in Core packages"
