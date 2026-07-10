#!/usr/bin/env python3
"""Multi-input signing gate — requires high/medium multi-in cases PASS."""
from __future__ import print_function

import os
import subprocess
import sys
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CLI_DIR = os.path.join(SCRIPT_DIR, "..")
BIN = os.path.join(CLI_DIR, "fktsigner")
HARNESS = os.path.join(SCRIPT_DIR, "run_sparrow_real_harness.py")

# Must appear as PASS in harness output (multi-input coverage).
REQUIRED = [
    "p2wpkh_2in_2out",
    "p2wpkh_3in_1out",
    "p2tr_2in_2out",
    "mixed_p2wpkh_p2tr_2in_2out",
]


def main():
    if not os.path.isfile(BIN):
        print("missing fktsigner", file=sys.stderr)
        return 1
    env = os.environ.copy()
    env["FKT_NO_CONFIRM"] = "1"
    # Default harness = high+medium+low (covers 2in and 3in multi-input).
    p = subprocess.Popen(
        [sys.executable, HARNESS],
        cwd=CLI_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    out, _ = p.communicate()
    text = out.decode("utf-8", "replace")
    print(text)
    if p.returncode != 0:
        print("FAIL harness rc=%s" % p.returncode)
        return 1
    if "FAIL=" in text and "FAIL=0" not in text.split("Results:")[-1]:
        # allow Results: PASS=N FAIL=0
        if "FAIL=0" not in text:
            print("FAIL harness reported failures")
            return 1

    missing = []
    for cid in REQUIRED:
        # line like: p2wpkh_2in_2out  PASS  ...
        ok = False
        for line in text.splitlines():
            if line.strip().startswith(cid) and "PASS" in line:
                ok = True
                break
        if not ok:
            missing.append(cid)

    if missing:
        print("FAIL multi-input cases not PASS:", ", ".join(missing))
        return 1

    print("PASS multi-input gate (%d cases)" % len(REQUIRED))
    return 0


if __name__ == "__main__":
    sys.exit(main())
