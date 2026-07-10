#!/usr/bin/env bash
# stage_floppy.sh — assemble Ice Cold DOS floppy tree (not a raw .img)
#
# Contents (8.3-friendly):
#   FKTSIGN.EXE   stripped DOS signer
#   CWSDPMI.EXE   DPMI host
#   README.TXT    short run notes (from cli/docs/DOS_README.TXT)
#
# Usage: scripts/stage_floppy.sh [out_dir]
# Default out_dir: dist/floppy-iced-cold

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist/floppy-iced-cold}"
CLI="$ROOT/cli"
DJGPP_BIN="$ROOT/tools/djgpp/bin"
STRIP="$DJGPP_BIN/i586-pc-msdosdjgpp-strip"

export PATH="$DJGPP_BIN:$PATH"
export LD_LIBRARY_PATH="$ROOT/tools/djgpp/lib/host:${LD_LIBRARY_PATH:-}"

echo "== Building DOS release (strip) =="
make -C "$CLI" -f Makefile.dos clean
make -C "$CLI" -f Makefile.dos all

if [[ ! -f "$CLI/FKTSIGN.EXE" ]]; then
  echo "FAIL: FKTSIGN.EXE not produced"
  exit 1
fi

mkdir -p "$OUT"
rm -f "$OUT"/* 2>/dev/null || true

cp -a "$CLI/FKTSIGN.EXE" "$OUT/FKTSIGN.EXE"
if [[ -x "$STRIP" ]]; then
  "$STRIP" "$OUT/FKTSIGN.EXE"
  echo "stripped FKTSIGN.EXE"
fi

CWSDPMI=""
for c in "$CLI/CWSDPMI.EXE" "$ROOT/tools/cwsdpmi/CWSDPMI.EXE"; do
  if [[ -f "$c" ]]; then
    CWSDPMI="$c"
    break
  fi
done
if [[ -z "$CWSDPMI" ]]; then
  echo "FAIL: CWSDPMI.EXE not found (cli/ or tools/cwsdpmi/)"
  exit 1
fi
cp -a "$CWSDPMI" "$OUT/CWSDPMI.EXE"

# DOS text: CRLF optional; plain LF fine for FreeDOS editors
cp -a "$CLI/docs/DOS_README.TXT" "$OUT/README.TXT"

# Version stamp for the package
if [[ -f "$CLI/fkt_version.h" ]]; then
  ver="$(sed -n 's/.*FKT_VERSION_STRING \"\(.*\)\".*/\1/p' "$CLI/fkt_version.h" | head -1)"
  {
    echo "FKT Ice Cold floppy package"
    echo "version: ${ver:-unknown}"
    echo "built:   $(date -u +%Y-%m-%dT%H:%MZ)"
    echo "host:    $(uname -srm 2>/dev/null || echo unknown)"
    echo "files:   FKTSIGN.EXE CWSDPMI.EXE README.TXT"
  } > "$OUT/VERSION.TXT"
fi

echo "== Size audit =="
"$ROOT/scripts/check_floppy_size.sh" "$OUT/FKTSIGN.EXE"
"$ROOT/scripts/check_floppy_size.sh" --package "$OUT"

echo "== Staged: $OUT =="
ls -la "$OUT"
