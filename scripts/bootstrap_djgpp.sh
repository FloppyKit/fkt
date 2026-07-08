#!/usr/bin/env bash
# Install a local DJGPP cross-compiler (prebuilt tarball preferred).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${DJGPP_PREFIX:-$ROOT/tools/djgpp}"
GCC_VER="${DJGPP_GCC_VER:-12.2.0}"
BUILD_DIR="${DJGPP_BUILD_DIR:-$ROOT/tools/build-djgpp-src}"

if command -v "$PREFIX/bin/i586-pc-msdosdjgpp-gcc" >/dev/null 2>&1; then
  echo "DJGPP already installed at $PREFIX"
  "$PREFIX/bin/i586-pc-msdosdjgpp-gcc" -v
  exit 0
fi

mkdir -p "$(dirname "$PREFIX")"

arch="$(uname -m)"
case "$arch" in
  x86_64) TARBALL="djgpp-linux64-gcc1220.tar.bz2" ;;
  i686|i386) TARBALL="djgpp-linux32-gcc1220.tar.bz2" ;;
  *)
    echo "Unsupported host arch for prebuilt DJGPP: $arch" >&2
    TARBALL=""
    ;;
esac

if [ -n "$TARBALL" ]; then
  URL="https://github.com/andrewwutw/build-djgpp/releases/download/v3.4/$TARBALL"
  TMP="$(mktemp -d)"
  echo "Downloading prebuilt DJGPP ($TARBALL)..."
  curl -fsSL -o "$TMP/$TARBALL" "$URL"
  rm -rf "$PREFIX"
  mkdir -p "$PREFIX"
  tar -xjf "$TMP/$TARBALL" -C "$PREFIX" --strip-components=1
  rm -rf "$TMP"
  mkdir -p "$PREFIX/lib/host"
  if ! LD_LIBRARY_PATH="$PREFIX/lib/host${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
      "$PREFIX/bin/i586-pc-msdosdjgpp-ar" --version >/dev/null 2>&1; then
    echo "Fetching libfl2 for DJGPP binutils..."
    FL_TMP="$(mktemp -d)"
    curl -fsSL -o "$FL_TMP/libfl2.deb" \
      "http://us.archive.ubuntu.com/ubuntu/pool/main/f/flex/libfl2_2.6.4-8.2build1_amd64.deb"
    dpkg-deb -x "$FL_TMP/libfl2.deb" "$FL_TMP/extract"
    cp "$FL_TMP/extract/usr/lib/"*/libfl.so.2* "$PREFIX/lib/host/"
    rm -rf "$FL_TMP"
  fi
  echo "DJGPP prebuilt installed to $PREFIX"
  "$PREFIX/bin/i586-pc-msdosdjgpp-gcc" -v
  exit 0
fi

echo "Prebuilt DJGPP unavailable; building from source (requires bison, flex, texinfo, gperf)..."

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required tool: $1" >&2
    exit 1
  }
}

need_cmd gcc
need_cmd g++
need_cmd make
need_cmd curl
need_cmd bison
need_cmd flex
need_cmd texinfo
need_cmd gperf

if [ ! -d "$BUILD_DIR/.git" ]; then
  rm -rf "$BUILD_DIR"
  git clone --depth 1 https://github.com/andrewwutw/build-djgpp.git "$BUILD_DIR"
fi

export DJGPP_PREFIX="$PREFIX"
export PATH="$PREFIX/bin:$PATH"
mkdir -p "$PREFIX"

cd "$BUILD_DIR"
./build-djgpp.sh "${DJGPP_GCC_VER:-10.3.0}"

echo ""
echo "DJGPP installed to $PREFIX"
"$PREFIX/bin/i586-pc-msdosdjgpp-gcc" -v