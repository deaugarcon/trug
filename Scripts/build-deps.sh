#!/bin/bash
# Builds the libimobiledevice stack from pinned source into Vendor/.
# Host-arch dev builds; universal+static-SSL arrives with the SP4 packaging plan.
# To force a full rebuild: rm -rf Vendor/
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="$ROOT/Vendor"; SRC="$VENDOR/src"
# shellcheck source=deps.lock
source "$ROOT/Scripts/deps.lock"
if ! command -v brew &>/dev/null; then
  echo "ERROR: Homebrew is required. Install from https://brew.sh" >&2; exit 1
fi
if ! brew list openssl@3 &>/dev/null; then
  echo "ERROR: openssl@3 is required. Run: brew install openssl@3" >&2; exit 1
fi
mkdir -p "$SRC"
# macOS ships libcurl but without a .pc file in standard paths; use the Homebrew-provided
# stub (needed by libtatsu). Fall back to the previous major if this macOS version has no dir.
_MACOS_MAJOR=$(sw_vers -productVersion | cut -d. -f1)
_PC_BASE="$(brew --repository)/Library/Homebrew/os/mac/pkgconfig"
_CURL_PC_DIR=""
for _v in "$_MACOS_MAJOR" "$((_MACOS_MAJOR - 1))"; do
  if [ -d "$_PC_BASE/$_v" ]; then _CURL_PC_DIR="$_PC_BASE/$_v"; break; fi
done
if [ -z "$_CURL_PC_DIR" ]; then
  echo "WARN: no Homebrew libcurl.pc stub under $_PC_BASE for macOS $_MACOS_MAJOR; libtatsu may fail to configure" >&2
fi
export PKG_CONFIG_PATH="$VENDOR/lib/pkgconfig:$(brew --prefix openssl@3)/lib/pkgconfig${_CURL_PC_DIR:+:$_CURL_PC_DIR}"
export CFLAGS="-I$VENDOR/include" LDFLAGS="-L$VENDOR/lib"

# Stamps are ref-aware: bumping a ref in deps.lock invalidates that lib's stamp. After bumping
# a lower-level lib's ref, rm -rf Vendor/ is still the safe path — dependents won't rebuild against it automatically.
build() { # name repo ref [configure flags...]
  local name="$1" repo="$2" ref="$3"; shift 3
  local dir="$SRC/$name" stamp="$VENDOR/.built_$name"
  if [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$ref" ]; then
    echo "== skipped $name (already built @ $ref; rm -rf Vendor/ to force rebuild)"; return 0
  fi
  if [ ! -d "$dir" ]; then git clone "$repo" "$dir"; fi
  git -C "$dir" fetch --tags --quiet
  git -C "$dir" fetch --quiet origin "$ref" 2>/dev/null || true
  git -C "$dir" checkout --quiet "$ref"
  ( cd "$dir" && ./autogen.sh --prefix="$VENDOR" "$@" && make -j"$(sysctl -n hw.ncpu)" && make install )
  echo "$ref" > "$stamp"
  echo "== built $name @ $ref"
}

build libplist https://github.com/libimobiledevice/libplist "$LIBPLIST_REF" --without-cython
build libimobiledevice-glue https://github.com/libimobiledevice/libimobiledevice-glue "$GLUE_REF"
build libusbmuxd https://github.com/libimobiledevice/libusbmuxd "$LIBUSBMUXD_REF"
build libtatsu https://github.com/libimobiledevice/libtatsu "$LIBTATSU_REF"
build libimobiledevice https://github.com/libimobiledevice/libimobiledevice "$LIBIMOBILEDEVICE_REF" --without-cython
echo "OK: Vendor ready at $VENDOR"
