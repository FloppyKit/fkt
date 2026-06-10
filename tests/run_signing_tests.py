#!/usr/bin/env python3
"""
Signing test runner for FKT.
Walks each unsigned PSBT in tests/golden-51/unsigned/,
extracts the derivation path from the PSBT, signs it with the
golden seed, and compares the output to the golden-signed file.
"""

import os, sys, subprocess, hashlib, struct
from pathlib import Path
from embit import psbt, bip32, networks

UNSIGNED_DIR   = "tests/golden-51/unsigned"
SIGNED_DIR     = "tests/golden-51/golden-signed"
GOLDEN_SEED_HEX = "dc26536673dd2912aae6863d2984566995154dcdd72c003ebf4dc61e7b93e710e9693f23cfc397ca71bc9362cefb95ab52896d0dc68cfae352b6d8dda13aaeaa"
BINARY         = "./fkt_sign_demo"

def extract_path_from_psbt(filepath):
    """Return the BIP32 derivation path string or None."""
    with open(filepath, 'rb') as f:
        raw = f.read()

    def read_varint(pos):
        v = raw[pos]
        if v < 0xfd:
            return v, pos + 1
        if v == 0xfd:
            return (raw[pos+1] | (raw[pos+2] << 8)), pos + 3
        if v == 0xfe:
            return (raw[pos+1] | (raw[pos+2] << 8) | (raw[pos+3] << 16) | (raw[pos+4] << 24)), pos + 5
        return 0, pos + 1

    pos = 5  # skip 'psbt\xff'
    # --- skip global map ---
    while pos < len(raw) and raw[pos] != 0x00:
        klen, pos = read_varint(pos)
        pos += klen
        vlen, pos = read_varint(pos)
        pos += vlen
    if pos >= len(raw) or raw[pos] != 0x00:
        return None
    pos += 1  # global separator

    # --- first input map ---
    while pos < len(raw) and raw[pos] != 0x00:
        klen, pos = read_varint(pos)
        key_type = raw[pos] if pos < len(raw) else 0
        pos += klen
        vlen, pos = read_varint(pos)
        val = raw[pos : pos + vlen]
        pos += vlen

        if key_type == 0x06 and len(val) >= 4:
            fp = struct.unpack('>I', val[:4])[0]
            indices = [struct.unpack('<I', val[i:i+4])[0] for i in range(4, len(val), 4)]
            path = "m/" + "/".join(
                str(idx & 0x7FFFFFFF) + ("'" if idx & 0x80000000 else "")
                for idx in indices
            )
            return path
    return None

def read_varint(buf, start):
    """Return varint value at buf[start]; advance pointer not modified."""
    v = buf[start]
    if v < 0xfd:
        return v, start+1
    if v == 0xfd:
        return (buf[start+1] | (buf[start+2]<<8)), start+3
    if v == 0xfe:
        return (buf[start+1] | (buf[start+2]<<8) | (buf[start+3]<<16) | (buf[start+4]<<24)), start+5
    return 0, start+1

def read_varint_advance(buf, pos):
    _, new_pos = read_varint(buf, pos)
    return new_pos

def run_sign(filepath, path):
    cmd = [BINARY, str(filepath), GOLDEN_SEED_HEX, path]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def compare_psbts(a_path, b_path):
    with open(a_path, 'rb') as a, open(b_path, 'rb') as b:
        return a.read() == b.read()

def main():
    unsigned = sorted(Path(UNSIGNED_DIR).glob("*.psbt"))
    stats = {"PASS": 0, "FAIL": 0, "SKIP": 0}
    for uf in unsigned:
        signed_file = Path(SIGNED_DIR) / uf.name
        if not signed_file.exists():
            print(f"SKIP   {uf.name}  (no golden-signed file)")
            stats["SKIP"] += 1
            continue

        path = extract_path_from_psbt(uf)
        if path is None:
            print(f"SKIP   {uf.name}  (no derivation path found)")
            stats["SKIP"] += 1
            continue

        if run_sign(uf, path):
            # Compare produced signed.psbt with golden
            if compare_psbts("signed.psbt", signed_file):
                print(f"PASS   {uf.name}")
                stats["PASS"] += 1
            else:
                print(f"FAIL   {uf.name}  (output mismatch)")
                stats["FAIL"] += 1
        else:
            print(f"FAIL   {uf.name}  (signer error)")
            stats["FAIL"] += 1

    total = sum(stats.values())
    print(f"\nPASS={stats['PASS']}  FAIL={stats['FAIL']}  SKIP={stats['SKIP']}  TOTAL={total}")

if __name__ == "__main__":
    main()