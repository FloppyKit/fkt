#!/usr/bin/env bash
# Verify DOS EXE fits floppy budget (default 1.20 MiB for FKTSIGNER.EXE alone).
set -euo pipefail

EXE="${1:-cli/FKTSIGN.EXE}"
MAX_BYTES="${FKT_FLOPPY_EXE_MAX:-1258291}"

if [ ! -f "$EXE" ]; then
  echo "Missing EXE: $EXE" >&2
  exit 1
fi

SIZE="$(wc -c < "$EXE" | tr -d ' ')"
echo "EXE size: $SIZE bytes (budget $MAX_BYTES)"

if [ "$SIZE" -gt "$MAX_BYTES" ]; then
  echo "FAIL: $EXE exceeds floppy EXE budget by $((SIZE - MAX_BYTES)) bytes" >&2
  exit 1
fi

echo "PASS: $EXE within floppy EXE budget"