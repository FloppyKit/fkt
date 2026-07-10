#!/usr/bin/env bash
# check_floppy_size.sh — Ice Cold floppy package budget (1.44 MB HD)
#
# Usage:
#   scripts/check_floppy_size.sh [FKTSIGN.EXE]
#   scripts/check_floppy_size.sh --package DIR
#
# Budget:
#   Single EXE soft cap: 1.20 MiB (historical DOS_TEST_STATUS)
#   Full package hard cap: 1.44 MB = 1_474_560 bytes (FKTSIGN + CWSDPMI + README)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Classic 1.44 MB 3.5" HD capacity (80×2×18×512)
FLOPPY_MAX=1474560
# Soft cap for EXE alone (leave room for CWSDPMI + docs)
EXE_SOFT=1258291   # 1.20 MiB

mode="exe"
path=""
if [[ "${1:-}" == "--package" ]]; then
  mode="package"
  path="${2:-}"
elif [[ -n "${1:-}" ]]; then
  path="$1"
else
  path="$ROOT/cli/FKTSIGN.EXE"
fi

bytes() {
  if [[ -f "$1" ]]; then
    wc -c < "$1" | tr -d ' '
  else
    echo 0
  fi
}

human() {
  local n="$1"
  if command -v numfmt >/dev/null 2>&1; then
    numfmt --to=iec-i --suffix=B "$n" 2>/dev/null || echo "${n} B"
  else
    echo "${n} B"
  fi
}

if [[ "$mode" == "exe" ]]; then
  if [[ ! -f "$path" ]]; then
    echo "FAIL: missing $path"
    exit 1
  fi
  sz="$(bytes "$path")"
  echo "EXE:     $path"
  echo "size:    $sz  ($(human "$sz"))"
  echo "soft:    $EXE_SOFT  ($(human "$EXE_SOFT"))  EXE alone"
  echo "floppy:  $FLOPPY_MAX  ($(human "$FLOPPY_MAX"))  full image"
  if [[ "$sz" -gt "$EXE_SOFT" ]]; then
    echo "FAIL: EXE exceeds 1.20 MiB soft budget"
    exit 1
  fi
  echo "PASS: EXE within soft budget"
  exit 0
fi

# Package mode: sum regular files in directory
if [[ ! -d "$path" ]]; then
  echo "FAIL: package dir missing: $path"
  exit 1
fi
total=0
echo "Package: $path"
while IFS= read -r -d '' f; do
  b="$(bytes "$f")"
  total=$((total + b))
  rel="${f#"$path"/}"
  printf "  %8d  %s\n" "$b" "$rel"
done < <(find "$path" -type f -print0 | sort -z)

echo "--------"
echo "total:   $total  ($(human "$total"))"
echo "limit:   $FLOPPY_MAX  ($(human "$FLOPPY_MAX"))"
if [[ "$total" -gt "$FLOPPY_MAX" ]]; then
  echo "FAIL: package exceeds 1.44 MB floppy"
  exit 1
fi
pct=$(( total * 100 / FLOPPY_MAX ))
echo "used:    ${pct}% of floppy"
echo "PASS: package fits 1.44 MB floppy"
exit 0
