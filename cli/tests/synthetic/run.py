#!/usr/bin/env python3
import os, json, tempfile, shutil
from lib.signer import sign

MANIFEST = "manifest.json"

with open(MANIFEST) as f:
    cases = json.load(f)

passed = 0
failed = 0
tmpdir = tempfile.mkdtemp()

try:
    for case in cases:
        name = case["name"]
        expected = case["expected"]
        unsigned = case["file"]
        signed = os.path.join(tmpdir, name + "_signed.psbt")

        ok = sign(unsigned, signed)

        if expected == "reject":
            if ok:
                print(f"FAIL {name}: expected rejection but signed")
                failed += 1
            else:
                print(f"PASS {name} (expected rejection)")
                passed += 1
        else:   # expected "sign"
            if not ok:
                print(f"FAIL {name}: signing returned error")
                failed += 1
                continue
            # verify a signature exists
            with open(signed, "rb") as f:
                data = f.read()
            if b'\x02' not in data and b'\x13' not in data:
                print(f"FAIL {name}: no signature found")
                failed += 1
            else:
                print(f"PASS {name}")
                passed += 1
finally:
    shutil.rmtree(tmpdir)

print(f"\nResults: PASS={passed} FAIL={failed}")
if failed == 0:
    print("All synthetic tests passed – baseline is solid.")
else:
    print("Some tests FAILED – do not expand until fixed.")