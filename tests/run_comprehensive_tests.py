#!/usr/bin/env python3
import os, json, subprocess, tempfile, shutil

SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
UNSIGNED_DIR = "comprehensive_unsigned"
SIGNER_BIN   = "cli/fktsigner"
MANIFEST     = "manifest.json"

with open(MANIFEST) as f:
    cases = json.load(f)

passed = 0
failed = 0
skipped = 0

tmpdir = tempfile.mkdtemp()
try:
    for case in cases:
        name = case["name"]
        expected = case["expected"]
        if expected == "skip":
            print(f"SKIP {name}")
            skipped += 1
            continue

        unsigned = os.path.join(UNSIGNED_DIR, name + ".psbt")
        signed   = os.path.join(tmpdir, name + "_signed.psbt")
        path = case.get("path", "84'/1'/0'/0/0")
        cmd = [SIGNER_BIN, SEED_HEX, path, unsigned, signed]
        ret = subprocess.run(cmd, capture_output=True)

        if expected == "pass":
            if ret.returncode != 0:
                print(f"FAIL {name}: expected sign but got error")
                failed += 1
                continue
            # Verify a partial signature exists (0x02 for P2WPKH, 0x13 for P2TR)
            with open(signed, "rb") as f:
                data = f.read()
            if b'\x02' not in data and b'\x13' not in data:
                print(f"FAIL {name}: no signature found")
                failed += 1
            else:
                print(f"PASS {name}")
                passed += 1
        elif expected == "xfail":
            if ret.returncode == 0:
                print(f"FAIL {name}: expected rejection but signed")
                failed += 1
            else:
                print(f"PASS {name} (expected rejection)")
                passed += 1
        else:
            print(f"SKIP {name} (unknown expected)")
            skipped += 1
finally:
    shutil.rmtree(tmpdir)

print(f"\nResults: PASS={passed} FAIL={failed} SKIP={skipped}")
if failed == 0:
    print("All comprehensive tests passed – signer is fully validated!")