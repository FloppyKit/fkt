#!/usr/bin/env bash
# Smoke-test FKTSIGNER.EXE under DOSBox (version/help only).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXE="${1:-$ROOT/cli/FKTSIGNER.EXE}"
CONF="$(mktemp)"

if [ ! -f "$EXE" ]; then
  echo "Missing EXE: $EXE" >&2
  exit 1
fi

if ! command -v dosbox >/dev/null 2>&1; then
  echo "dosbox not installed; skip smoke test" >&2
  exit 0
fi

cat >"$CONF" <<EOF
[autoexec]
@echo off
mount c $(dirname "$EXE")
c:
cd \\
FKTSIGNER.EXE --version
echo EXITCODE=%ERRORLEVEL%
exit
EOF

echo "Running DOSBox smoke: FKTSIGNER.EXE --version"
dosbox -conf "$CONF" -exit 2>&1 | tee /tmp/fkt_dosbox_smoke.log

if grep -q "FKT" /tmp/fkt_dosbox_smoke.log; then
  echo "PASS: DOSBox smoke saw version output"
else
  echo "WARN: DOSBox smoke did not find expected version string" >&2
  exit 1
fi

rm -f "$CONF"