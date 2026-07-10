#!/usr/bin/env bash
# dosbox_smoke.sh — run FKTSIGN.EXE --version under DOSBox
# Usage: scripts/dosbox_smoke.sh [path/to/FKTSIGN.EXE or package dir]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-$ROOT/dist/floppy-iced-cold}"

if [[ -d "$TARGET" ]]; then
  PKG="$TARGET"
elif [[ -f "$TARGET" ]]; then
  PKG="$(dirname "$TARGET")"
else
  echo "usage: $0 [FKTSIGN.EXE|package_dir]"
  exit 1
fi

if [[ ! -f "$PKG/FKTSIGN.EXE" ]]; then
  echo "missing $PKG/FKTSIGN.EXE — run scripts/stage_floppy.sh first"
  exit 1
fi

if ! command -v dosbox >/dev/null 2>&1; then
  echo "dosbox not installed; skip smoke (EXE still built)"
  exit 0
fi

export SDL_VIDEODRIVER="${SDL_VIDEODRIVER:-dummy}"
export SDL_AUDIODRIVER="${SDL_AUDIODRIVER:-dummy}"

CONF="$(mktemp /tmp/fkt-dosbox.XXXXXX.conf)"
OUT="$PKG/VER.OUT"
rm -f "$OUT"

cat > "$CONF" <<EOF
[sdl]
fullscreen=false
output=surface
[cpu]
cycles=max
[autoexec]
@echo off
mount c $PKG
c:
FKTSIGN.EXE --version > VER.OUT
exit
EOF

timeout 45 dosbox -conf "$CONF" -exit -noconsole >/dev/null 2>&1 || true
rm -f "$CONF"

if [[ ! -f "$OUT" ]]; then
  # DOS may uppercase
  if [[ -f "$PKG/ver.out" ]]; then OUT="$PKG/ver.out"; fi
fi

if [[ ! -f "$OUT" ]]; then
  echo "FAIL: no VER.OUT from DOSBox"
  exit 1
fi

ver="$(tr -d '\r' < "$OUT" | head -1)"
echo "DOSBox: $ver"
rm -f "$OUT" "$PKG/ver.out" 2>/dev/null || true
if echo "$ver" | grep -q 'fkt '; then
  echo "PASS dosbox_smoke"
  exit 0
fi
echo "FAIL: unexpected version output: $ver"
exit 1
