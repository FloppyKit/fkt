#!/usr/bin/env python3
"""V2 multisig regression: 1-of-1 finalize, 2-of-2 / 2-of-3 cosign.

Uses synthetic fixtures from gen_multisig_vector + fktsigner hex harness.
TESTNET-ONLY seeds (same as TEST_SEEDS.md).
"""
from __future__ import print_function

import hashlib
import os
import struct
import subprocess
import sys
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CLI_DIR = os.path.join(SCRIPT_DIR, "..")
SIGNER = os.path.join(CLI_DIR, "fktsigner")
GEN = os.path.join(SCRIPT_DIR, "gen_multisig_vector")
PATH = "m/48'/1'/0'/2'/0/0"  # unused when PSBT has derivations; placeholder OK

MNEMONICS = {
    "A": (
        "call release rib regret puzzle magic economy tragic various "
        "embody give road"
    ),
    "B": (
        "reward parade plug shop winner melt leg unfold sand side shell "
        "receive vague miracle day wall pear season upper monkey wear "
        "duck paper brush"
    ),
    "C": (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about"
    ),
}


def mnemonic_to_seed_hex(mnemonic):
    words = " ".join(mnemonic.strip().split())
    seed = hashlib.pbkdf2_hmac(
        "sha512", words.encode("utf-8"), b"mnemonic", 2048, 64
    )
    return seed.hex()


SEEDS = {k: mnemonic_to_seed_hex(v) for k, v in MNEMONICS.items()}


def read_varint(raw, pos):
    v = raw[pos]
    if v < 0xFD:
        return v, pos + 1
    if v == 0xFD:
        return raw[pos + 1] | (raw[pos + 2] << 8), pos + 3
    raise ValueError("varint")


def input_maps(raw):
    """Return list of input map dicts key->value after global."""
    if raw[:5] != b"psbt\xff":
        raise ValueError("not psbt")
    pos = 5
    # skip global
    while pos < len(raw) and raw[pos] != 0:
        klen, pos = read_varint(raw, pos)
        pos += klen
        vlen, pos = read_varint(raw, pos)
        pos += vlen
    pos += 1  # sep
    maps = []
    while pos < len(raw):
        m = {}
        if raw[pos] == 0 and not m:
            # empty map then maybe outputs
            pass
        while pos < len(raw) and raw[pos] != 0:
            klen, pos = read_varint(raw, pos)
            key = raw[pos : pos + klen]
            pos += klen
            vlen, pos = read_varint(raw, pos)
            val = raw[pos : pos + vlen]
            pos += vlen
            m[key] = val
        maps.append(m)
        pos += 1  # sep
        # stop after first input for our 1-in fixtures; still consume cleanly
        if len(maps) >= 1:
            break
    return maps


def has_partial_sig(raw):
    for m in input_maps(raw):
        for k in m:
            if len(k) == 34 and k[0] == 0x02:
                return True
    return False


def has_final_witness(raw):
    for m in input_maps(raw):
        for k in m:
            if k == b"\x08":
                return True
    return False


def count_partial_sigs(raw):
    n = 0
    for m in input_maps(raw):
        for k in m:
            if len(k) == 34 and k[0] == 0x02:
                n += 1
    return n


def run_sign(seed_hex, inp, out):
    """Dev harness: seed path in out. Skip confirm via FKT_NO_CONFIRM."""
    env = os.environ.copy()
    env["FKT_NO_CONFIRM"] = "1"
    cmd = [SIGNER, seed_hex, PATH, inp, out]
    p = subprocess.Popen(
        cmd,
        cwd=CLI_DIR,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    out_b, err_b = p.communicate(b"\n")
    return p.returncode, out_b.decode("utf-8", "replace"), err_b.decode("utf-8", "replace")


def gen(kind, path, *seed_keys):
    args = [GEN, kind, path] + [SEEDS[k] for k in seed_keys]
    r = subprocess.run(args, cwd=CLI_DIR, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(
            "gen failed: %s\n%s" % (r.stderr.decode("utf-8", "replace"), r.stdout)
        )


def main():
    if not os.path.isfile(SIGNER):
        print("FAIL: build fktsigner first", file=sys.stderr)
        return 1
    if not os.path.isfile(GEN):
        print("FAIL: build gen_multisig_vector first", file=sys.stderr)
        return 1

    fails = 0
    tmp = tempfile.mkdtemp(prefix="fkt-multi-")
    print("V2 multisig tests (workdir %s)" % tmp)

    # --- 1-of-1: one sign → final witness ---
    u1 = os.path.join(tmp, "1of1.psbt")
    s1 = os.path.join(tmp, "1of1.signed.psbt")
    gen("1of1", u1, "A")
    rc, so, se = run_sign(SEEDS["A"], u1, s1)
    raw = open(s1, "rb").read() if os.path.isfile(s1) else b""
    if rc != 0 or not has_final_witness(raw):
        print("FAIL 1of1 finalize rc=%d final=%s" % (rc, has_final_witness(raw)))
        print(so[-400:] if so else "", se[-400:] if se else "")
        fails += 1
    else:
        print("PASS 1of1 → FINALIZED")

    # --- 2-of-2: A only → partial; A then B → final ---
    u2 = os.path.join(tmp, "2of2.psbt")
    s2a = os.path.join(tmp, "2of2.a.psbt")
    s2b = os.path.join(tmp, "2of2.ab.psbt")
    gen("2of2", u2, "A", "B")
    rc, so, se = run_sign(SEEDS["A"], u2, s2a)
    raw = open(s2a, "rb").read() if os.path.isfile(s2a) else b""
    if rc != 0 or not has_partial_sig(raw) or has_final_witness(raw):
        print(
            "FAIL 2of2 first cosign rc=%d partial=%s final=%s n=%d"
            % (rc, has_partial_sig(raw), has_final_witness(raw), count_partial_sigs(raw))
        )
        print(so[-400:] if so else "", se[-400:] if se else "")
        fails += 1
    else:
        print("PASS 2of2 cosign A → PARTIAL (n=%d)" % count_partial_sigs(raw))

    rc, so, se = run_sign(SEEDS["B"], s2a, s2b)
    raw = open(s2b, "rb").read() if os.path.isfile(s2b) else b""
    if rc != 0 or not has_final_witness(raw):
        print("FAIL 2of2 second cosign finalize rc=%d final=%s" % (rc, has_final_witness(raw)))
        print(so[-400:] if so else "", se[-400:] if se else "")
        fails += 1
    else:
        print("PASS 2of2 cosign B → FINALIZED")

    # --- 2-of-3: A only partial; A+B finalize (C unused) ---
    u3 = os.path.join(tmp, "2of3.psbt")
    s3a = os.path.join(tmp, "2of3.a.psbt")
    s3b = os.path.join(tmp, "2of3.ab.psbt")
    gen("2of3", u3, "A", "B", "C")
    rc, so, se = run_sign(SEEDS["A"], u3, s3a)
    raw = open(s3a, "rb").read() if os.path.isfile(s3a) else b""
    if rc != 0 or not has_partial_sig(raw) or has_final_witness(raw):
        print("FAIL 2of3 first cosign rc=%d" % rc)
        fails += 1
    else:
        print("PASS 2of3 cosign A → PARTIAL")

    rc, so, se = run_sign(SEEDS["B"], s3a, s3b)
    raw = open(s3b, "rb").read() if os.path.isfile(s3b) else b""
    if rc != 0 or not has_final_witness(raw):
        print("FAIL 2of3 A+B finalize rc=%d final=%s" % (rc, has_final_witness(raw)))
        print(so[-500:] if so else "", se[-500:] if se else "")
        fails += 1
    else:
        print("PASS 2of3 cosign B (threshold) → FINALIZED")

    # --- wrong seed on 2of2 must not sign ---
    u2w = os.path.join(tmp, "2of2.wrong.psbt")
    s2w = os.path.join(tmp, "2of2.wrong.out.psbt")
    gen("2of2", u2w, "A", "B")
    rc, so, se = run_sign(SEEDS["C"], u2w, s2w)
    if rc == 0:
        print("FAIL 2of2 wrong seed should fail (rc=0)")
        fails += 1
    else:
        print("PASS 2of2 wrong seed rejected")

    if fails:
        print("FAIL test-multisig (%d failures)" % fails)
        return 1
    print("PASS test-multisig (all cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
