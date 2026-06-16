#!/usr/bin/env python3
"""Real Sparrow tests using pre‑derived keypairs (bypasses secp256k1 bug)."""
import os, subprocess
from embit import bip32, networks

SCRIPT_DIR = os.path.dirname(__file__)
SIGNER_BIN = os.path.join(SCRIPT_DIR, "..", "fktsigner")

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

def get_keypair(seed_hex, path_str):
    seed = bytes.fromhex(seed_hex)
    root = bip32.HDKey.from_seed(seed, version=networks.NETWORKS['test']['xprv'])
    child = root.derive([int(x[:-1]) + 0x80000000 if x.endswith("'") else int(x) for x in path_str.split('/')[1:]])
    return child.key.secret, child.to_public().sec()

p2wpkh_priv, p2wpkh_pub = get_keypair(SEEDS["v1_p2wpkh"], PATHS["v1_p2wpkh"])
taproot_priv, taproot_pub = get_keypair(SEEDS["v1_p2tr"], PATHS["v1_p2tr"])

passed = 0
failed = 0

for filename in sorted(os.listdir(UNSIGNED_DIR)):
    if not filename.endswith(".psbt"):
        continue
    unsigned = os.path.join(UNSIGNED_DIR, filename)
    ours     = os.path.join(OUTPUT_DIR, filename)
    theirs   = os.path.join(SIGNED_DIR, filename)

    if filename.startswith("v1_p2wpkh"):
        priv, pub = p2wpkh_priv, p2wpkh_pub
    elif filename.startswith("v1_p2tr"):
        priv, pub = taproot_priv, taproot_pub
    else:
        continue

    cmd = [SIGNER_BIN, "--keypair", priv.hex(), pub.hex(), unsigned, ours]
    ret = subprocess.run(cmd, capture_output=True)

    if ret.returncode != 0:
        print(f"FAIL {filename}: signer error")
        failed += 1
        continue

    with open(ours, "rb") as f: our_data = f.read()
    with open(theirs, "rb") as f: their_data = f.read()

    if our_data == their_data:
        print(f"PASS {filename}")
        passed += 1
    else:
        print(f"FAIL {filename}: output differs")
        failed += 1

print(f"\nResults: PASS={passed} FAIL={failed}")