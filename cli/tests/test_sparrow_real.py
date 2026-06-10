#!/usr/bin/env python3
"""Sign real Sparrow PSBTs with fktsigner and compare byte‑for‑byte."""
import os, subprocess

SCRIPT_DIR = os.path.dirname(__file__)                         # .../cli/tests
SIGNER_BIN = os.path.join(SCRIPT_DIR, "..", "fktsigner")      # .../cli/fktsigner

SEEDS = {
    "v1_p2wpkh": "46b6b71e4a52ba6259aae7a9eaa991aea07fead2850cb9710aea4b234b73dcc26f21d986924ec4224f0fff3b2c73788de8e1f925451b79fcccbed9951b9b184d",
    "v1_p2tr":   "dc26536673dd2912aae6863d2984566995154dcdd72c003ebf4dc61e7b93e710e9693f23cfc397ca71bc9362cefb95ab52896d0dc68cfae352b6d8dda13aaeaa",
}

PATHS = {
    "v1_p2wpkh": "84'/1'/0'/0/0",
    "v1_p2tr":   "86'/1'/0'/0/0",
}

UNSIGNED_DIR = os.path.join(SCRIPT_DIR, "sparrow-real", "Unsigned", "v1")
SIGNED_DIR   = os.path.join(SCRIPT_DIR, "sparrow-real", "Signed", "v1")
OUTPUT_DIR   = os.path.join(SCRIPT_DIR, "sparrow-real", "output")

os.makedirs(OUTPUT_DIR, exist_ok=True)

passed = 0
failed = 0

for filename in sorted(os.listdir(UNSIGNED_DIR)):
    if not filename.endswith(".psbt"):
        continue

    seed_hex = None
    path = None
    for prefix in SEEDS:
        if filename.startswith(prefix):
            seed_hex = SEEDS[prefix]
            path = PATHS[prefix]
            break

    if seed_hex is None:
        print(f"SKIP {filename} (unknown prefix)")
        continue

    unsigned = os.path.join(UNSIGNED_DIR, filename)
    ours     = os.path.join(OUTPUT_DIR, filename)
    theirs   = os.path.join(SIGNED_DIR, filename)

    cmd = [SIGNER_BIN, seed_hex, path, unsigned, ours]
    ret = subprocess.run(cmd, capture_output=True, text=True)

    if ret.returncode != 0:
        err = ret.stderr.strip() if ret.stderr else "unknown"
        print(f"FAIL {filename}: signer returned error: {err}")
        failed += 1
        continue

    with open(ours, "rb") as f:
        our_data = f.read()
    with open(theirs, "rb") as f:
        their_data = f.read()

    if our_data == their_data:
        print(f"PASS {filename}")
        passed += 1
    else:
        print(f"FAIL {filename}: output differs")
        failed += 1

print(f"\nResults: PASS={passed} FAIL={failed}")
if failed == 0:
    print("All Sparrow real PSBTs matched – signer is fully verified!")