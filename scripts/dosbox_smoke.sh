#!/usr/bin/env bash
# Smoke-test DOS EXE under DOSBox (version string via OUT.TXT).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXE="${1:-$ROOT/cli/FKTSIGN.EXE}"
STAGE="${FKT_DOS_STAGE:-/tmp/fkt-dos-smoke}"
CONF="$(mktemp)"
OUT_LOG="/tmp/fkt_dosbox_smoke.log"
CWSDPMI_ZIP_URL="${CWSDPMI_ZIP_URL:-https://www.ibiblio.org/pub/micro/pc-stuff/freedos/files/util/system/cwsdpmi/csdpmi7b.zip}"

if [ ! -f "$EXE" ]; then
  echo "Missing EXE: $EXE" >&2
  echo "Hint: cd cli && make -f Makefile.dos   (produces FKTSIGN.EXE)" >&2
  exit 1
fi

if ! command -v dosbox >/dev/null 2>&1; then
  echo "dosbox not installed; skip smoke test" >&2
  exit 0
fi

mkdir -p "$STAGE"
cp -f "$EXE" "$STAGE/FKTSIGN.EXE"

if [ ! -f "$STAGE/CWSDPMI.EXE" ]; then
  if [ ! -f "$ROOT/tools/cwsdpmi/CWSDPMI.EXE" ]; then
    echo "Fetching CWSDPMI.EXE (required by DJGPP stub)..."
    TMP_ZIP="$(mktemp)"
    curl -fsSL -o "$TMP_ZIP" "$CWSDPMI_ZIP_URL"
    mkdir -p "$ROOT/tools/cwsdpmi"
    unzip -o -j "$TMP_ZIP" bin/CWSDPMI.EXE -d "$ROOT/tools/cwsdpmi"
    rm -f "$TMP_ZIP"
  fi
  cp -f "$ROOT/tools/cwsdpmi/CWSDPMI.EXE" "$STAGE/CWSDPMI.EXE"
fi

rm -f "$STAGE/OUT.TXT"

cat >"$CONF" <<EOF
[midi]
mpu401=none
mididevice=none
[dosbox]
memsize=31
[dos]
xms=true
ems=true
[dpmi]
dpmi=true
[autoexec]
@echo off
mount c $STAGE
c:
FKTSIGN.EXE --version > OUT.TXT
exit
EOF

echo "Running DOSBox smoke: FKTSIGN.EXE --version"
dosbox -conf "$CONF" -exit 2>&1 | tee "$OUT_LOG" || true

if [ -f "$STAGE/OUT.TXT" ] && grep -qi 'fkt' "$STAGE/OUT.TXT"; then
  echo "PASS: DOSBox smoke saw version output:"
  tr -d '\r' < "$STAGE/OUT.TXT"
  rm -f "$CONF"
  exit 0
fi

echo "FAIL: expected 'fkt' in $STAGE/OUT.TXT" >&2
if [ -f "$STAGE/OUT.TXT" ]; then
  echo "OUT.TXT contents:" >&2
  tr -d '\r' < "$STAGE/OUT.TXT" >&2
else
  echo "(OUT.TXT not created — check CWSDPMI.EXE and DOS 8.3 filename)" >&2
fi
rm -f "$CONF"
exit 1