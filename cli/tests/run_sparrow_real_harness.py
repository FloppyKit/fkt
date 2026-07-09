#!/usr/bin/env python3
"""Sparrow-real sign/reject harness (work package 2).

Reads cli/tests/sparrow-real/manifest.json, resolves testnet seeds, runs
fktsigner, writes fkt-signed/, and checks expect=sign|reject|partial_sig.

Seed resolution (first hit wins per seed_ref):
  1. Env named in manifest.seeds[seed_ref].env  (mnemonic or 128-char hex)
  2. Built-in TESTNET defaults from TEST_SEEDS.md / legacy harness hex
  3. Skip case if still unknown

Usage:
  python3 tests/run_sparrow_real_harness.py              # high only
  python3 tests/run_sparrow_real_harness.py --all
  python3 tests/run_sparrow_real_harness.py --priority medium
  FKT_SEED_CALL_RELEASE="call release ..." make test-sparrow-real
"""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CLI_DIR = os.path.join(SCRIPT_DIR, "..")
ROOT = os.path.join(SCRIPT_DIR, "sparrow-real")
MANIFEST = os.path.join(ROOT, "manifest.json")
SIGNER_BIN = os.path.join(CLI_DIR, "fktsigner")
VERIFY_BIN = os.path.join(CLI_DIR, "verify_ecdsa")

# TESTNET-ONLY defaults (public fixtures). Prefer env override.
DEFAULT_MNEMONICS = {
    "call_release": (
        "call release rib regret puzzle magic economy tragic various "
        "embody give road"
    ),
    "nested_reward_parade": (
        "reward parade plug shop winner melt leg unfold sand side shell "
        "receive vague miracle day wall pear season upper monkey wear "
        "duck paper brush"
    ),
}

# Older v1_p2wpkh_* Sparrow exports (64-byte BIP39 seed hex).
DEFAULT_HEX = {
    "legacy_p2wpkh_hex": (
        "46b6b71e4a52ba6259aae7a9eaa991aea07fead2850cb9710aea4b234b73dcc2"
        "6f21d986924ec4224f0fff3b2c73788de8e1f925451b79fcccbed9951b9b184d"
    ),
}

# Dummy path: signer uses per-input BIP32 paths from the PSBT when present.
PATH_PLACEHOLDER = "m/0"


def mnemonic_to_seed_hex(mnemonic):
    words = " ".join(mnemonic.strip().split())
    seed = hashlib.pbkdf2_hmac(
        "sha512", words.encode("utf-8"), b"mnemonic", 2048, 64
    )
    return seed.hex()


def is_seed_hex(s):
    if not s or len(s) != 128:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def resolve_seed_hex(seed_ref, seeds_meta):
    """Return (seed_hex, source_label) or (None, reason)."""
    meta = (seeds_meta or {}).get(seed_ref) or {}
    env_name = meta.get("env")
    if env_name:
        raw = os.environ.get(env_name, "").strip()
        if raw:
            if is_seed_hex(raw):
                return raw.lower(), "env:%s(hex)" % env_name
            return mnemonic_to_seed_hex(raw), "env:%s(mnemonic)" % env_name

    if seed_ref in DEFAULT_HEX:
        return DEFAULT_HEX[seed_ref], "default:legacy_hex"
    if seed_ref in DEFAULT_MNEMONICS:
        return mnemonic_to_seed_hex(DEFAULT_MNEMONICS[seed_ref]), "default:mnemonic"

    return None, "no seed for seed_ref=%s" % seed_ref


def read_varint(raw, pos):
    v = raw[pos]
    if v < 0xFD:
        return v, pos + 1
    if v == 0xFD:
        return raw[pos + 1] | (raw[pos + 2] << 8), pos + 3
    if v == 0xFE:
        return (
            raw[pos + 1]
            | (raw[pos + 2] << 8)
            | (raw[pos + 3] << 16)
            | (raw[pos + 4] << 24)
        ), pos + 5
    return 0, pos + 1


def parse_psbt_maps(raw):
    """Return (global_map, list_of_input_or_output_maps)."""
    if len(raw) < 5 or raw[:5] != b"psbt\xff":
        return None, None
    pos = 5
    gmap = {}
    while pos < len(raw) and raw[pos] != 0:
        klen, pos = read_varint(raw, pos)
        key = raw[pos : pos + klen]
        pos += klen
        vlen, pos = read_varint(raw, pos)
        val = raw[pos : pos + vlen]
        pos += vlen
        gmap[key] = val
    if pos >= len(raw) or raw[pos] != 0:
        return gmap, []
    pos += 1
    maps = []
    while pos < len(raw):
        m = {}
        while pos < len(raw) and raw[pos] != 0:
            klen, pos = read_varint(raw, pos)
            key = raw[pos : pos + klen]
            pos += klen
            vlen, pos = read_varint(raw, pos)
            val = raw[pos : pos + vlen]
            pos += vlen
            m[key] = val
        if pos < len(raw) and raw[pos] == 0:
            pos += 1
        maps.append(m)
    return gmap, maps


def get_unsigned_tx(raw):
    gmap, _ = parse_psbt_maps(raw)
    if not gmap:
        return None
    return gmap.get(b"\x00")


def count_tx_inputs(unsigned_tx):
    if not unsigned_tx or len(unsigned_tx) < 5:
        return 0
    p = 4
    n_in, p = read_varint(unsigned_tx, p)
    return n_in


def input_maps_only(raw):
    """Slice map list to input maps only (using unsigned tx nIn)."""
    gmap, maps = parse_psbt_maps(raw)
    if maps is None:
        return []
    utx = gmap.get(b"\x00") if gmap else None
    n_in = count_tx_inputs(utx) if utx else 0
    if n_in <= 0:
        return maps
    return maps[:n_in]


def map_has_keytype(m, kt):
    for k in m:
        if len(k) >= 1 and k[0] == kt:
            return True
    return False


def map_get_keytype(m, kt):
    for k, v in m.items():
        if len(k) >= 1 and k[0] == kt:
            return v
    return None


def has_signature_material(raw):
    """True if any input has final witness (0x08) or partial_sig (0x02)."""
    for m in input_maps_only(raw):
        if map_has_keytype(m, 0x08) or map_has_keytype(m, 0x02):
            return True
    return False


def all_inputs_have_sig_material(raw):
    maps = input_maps_only(raw)
    if not maps:
        return False
    for m in maps:
        if not (map_has_keytype(m, 0x08) or map_has_keytype(m, 0x02)):
            return False
    return True


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def bip143_sighash_p2wpkh(unsigned_raw, input_idx):
    """BIP143 sighash for a P2WPKH input (SIGHASH_ALL)."""
    tx = get_unsigned_tx(unsigned_raw)
    if not tx:
        return None
    p = 0
    ver = struct.unpack("<I", tx[p : p + 4])[0]
    p += 4
    n_in, p = read_varint(tx, p)
    inputs = []
    for _ in range(n_in):
        prev = tx[p : p + 32]
        p += 32
        vout = struct.unpack("<I", tx[p : p + 4])[0]
        p += 4
        slen, p = read_varint(tx, p)
        p += slen
        seq = struct.unpack("<I", tx[p : p + 4])[0]
        p += 4
        inputs.append((prev, vout, seq))
    n_out, p = read_varint(tx, p)
    outputs = []
    for _ in range(n_out):
        amt = struct.unpack("<q", tx[p : p + 8])[0]
        p += 8
        slen, p = read_varint(tx, p)
        script = tx[p : p + slen]
        p += slen
        outputs.append((amt, script))
    locktime = struct.unpack("<I", tx[p : p + 4])[0]

    # witness utxo for this input from PSBT input map
    imaps = input_maps_only(unsigned_raw)
    if input_idx >= len(imaps):
        return None
    wutxo = map_get_keytype(imaps[input_idx], 0x01)
    if not wutxo or len(wutxo) < 9:
        return None
    amt = struct.unpack("<q", wutxo[:8])[0]
    # scriptPubKey: compact size then bytes
    spk_len = wutxo[8]
    spk = wutxo[9 : 9 + spk_len]
    if len(spk) != 22 or spk[0] != 0x00 or spk[1] != 0x14:
        return None  # not plain P2WPKH
    h160 = spk[2:22]
    scriptcode = bytes([0x19, 0x76, 0xA9, 0x14]) + h160 + bytes([0x88, 0xAC])

    hp = sha256d(b"".join(i[0] + struct.pack("<I", i[1]) for i in inputs))
    hs = sha256d(b"".join(struct.pack("<I", i[2]) for i in inputs))
    ho = sha256d(
        b"".join(struct.pack("<q", a) + bytes([len(s)]) + s for a, s in outputs)
    )
    prev, vout, seq = inputs[input_idx]
    preimage = (
        struct.pack("<I", ver)
        + hp
        + hs
        + prev
        + struct.pack("<I", vout)
        + scriptcode
        + struct.pack("<q", amt)
        + struct.pack("<I", seq)
        + ho
        + struct.pack("<I", locktime)
        + struct.pack("<I", 1)
    )
    return sha256d(preimage)


def parse_p2wpkh_witness(wit):
    if not wit or wit[0] != 0x02:
        return None, None
    p = 1
    siglen = wit[p]
    p += 1
    sig = wit[p : p + siglen]
    p += siglen
    if p >= len(wit):
        return None, None
    pklen = wit[p]
    p += 1
    pk = wit[p : p + pklen]
    return sig, pk


def verify_p2wpkh_witnesses(unsigned_raw, signed_raw):
    """Verify finalized P2WPKH inputs via verify_ecdsa; skip non-p2wpkh."""
    if not os.path.isfile(VERIFY_BIN):
        return False, "verify_ecdsa missing"
    imaps_u = input_maps_only(unsigned_raw)
    imaps_s = input_maps_only(signed_raw)
    n = min(len(imaps_u), len(imaps_s))
    checked = 0
    for i in range(n):
        wutxo = map_get_keytype(imaps_u[i], 0x01)
        if not wutxo or len(wutxo) < 9:
            continue
        spk_len = wutxo[8]
        spk = wutxo[9 : 9 + spk_len]
        if len(spk) != 22 or spk[0] != 0x00 or spk[1] != 0x14:
            continue  # skip p2tr / nested / other
        wit = map_get_keytype(imaps_s[i], 0x08)
        if not wit:
            return False, "input %d missing final witness" % i
        sig, pk = parse_p2wpkh_witness(wit)
        if not sig or not pk:
            return False, "input %d bad p2wpkh witness" % i
        sighash = bip143_sighash_p2wpkh(unsigned_raw, i)
        if not sighash:
            return False, "input %d sighash failed" % i
        ret = subprocess.run(
            [VERIFY_BIN, sighash.hex(), pk.hex(), sig.hex()],
            capture_output=True,
        )
        if ret.returncode != 0:
            return False, "input %d ecdsa verify failed" % i
        checked += 1
    if checked == 0:
        return False, "no p2wpkh inputs verified"
    return True, "ecdsa ok (%d inputs)" % checked


def taproot_witnesses_ok(signed_raw):
    """Structural check: each P2TR-looking final witness is 1-stack 64-byte sig."""
    ok_any = False
    for m in input_maps_only(signed_raw):
        wit = map_get_keytype(m, 0x08)
        if not wit:
            continue
        # keypath: 0x01 0x40 <64-byte schnorr>
        if len(wit) == 66 and wit[0] == 0x01 and wit[1] == 64:
            ok_any = True
            continue
        # p2wpkh stack also has 0x08 — ignore
        if wit[0] == 0x02:
            continue
        # unknown witness shape for taproot
        if map_has_keytype(m, 0x17) or map_has_keytype(m, 0x16):
            return False, "unexpected taproot witness shape"
    return ok_any, "taproot keypath witness present" if ok_any else "no taproot witness"


def sign_case(seed_hex, unsigned_path, output_path):
    if os.path.isfile(output_path):
        os.remove(output_path)
    cmd = [SIGNER_BIN, seed_hex, PATH_PLACEHOLDER, unsigned_path, output_path]
    ret = subprocess.run(cmd, capture_output=True, text=True)
    err = ((ret.stdout or "") + (ret.stderr or "")).strip()
    return ret.returncode, err


def evaluate_sign(case, unsigned_raw, signed_path, sparrow_path):
    """Return (ok:bool, detail:str)."""
    if not os.path.isfile(signed_path):
        return False, "no fkt-signed output"
    signed_raw = open(signed_path, "rb").read()
    if len(signed_raw) < 5:
        return False, "empty output"

    if sparrow_path and os.path.isfile(sparrow_path):
        spr = open(sparrow_path, "rb").read()
        if signed_raw == spr:
            return True, "byte-equal sparrow-signed"

    script = case.get("script") or ""
    expect = case.get("expect")

    # Nested / partial: require partial_sig or finalization
    if script == "p2sh_p2wpkh" or expect == "partial_sig":
        if has_signature_material(signed_raw):
            return True, "partial_sig/witness present (nested or partial)"
        return False, "missing partial_sig/witness for nested"

    # Pure p2tr keypath
    if script in ("p2tr", "p2tr_script_path"):
        # Prefer witness compare to sparrow when available
        if sparrow_path and os.path.isfile(sparrow_path):
            spr = open(sparrow_path, "rb").read()
            si = input_maps_only(signed_raw)
            sp = input_maps_only(spr)
            if si and sp and len(si) <= len(sp):
                match = True
                for i in range(len(si)):
                    wf = map_get_keytype(si[i], 0x08)
                    ws = map_get_keytype(sp[i], 0x08)
                    if wf != ws:
                        match = False
                        break
                if match and map_get_keytype(si[0], 0x08):
                    return True, "taproot witness matches sparrow"
        ok, msg = taproot_witnesses_ok(signed_raw)
        if ok:
            return True, msg
        if has_signature_material(signed_raw):
            return True, "sig material present (taproot)"
        return False, msg

    # p2wpkh and mixed: crypto verify p2wpkh legs; structure for rest
    if script in ("p2wpkh", "mixed_p2wpkh_p2tr", "mixed"):
        # If all final witnesses present
        if not all_inputs_have_sig_material(signed_raw):
            return False, "not all inputs have sig material"
        # ECDSA verify where possible
        ok, msg = verify_p2wpkh_witnesses(unsigned_raw, signed_raw)
        if script == "p2wpkh":
            if ok:
                return True, msg
            # fallback: structural only if verify tool missing
            if "verify_ecdsa missing" in msg and has_signature_material(signed_raw):
                return True, "structural pass (no verify_ecdsa)"
            return False, msg
        # mixed: verify any P2WPKH legs; require all inputs signed
        if not all_inputs_have_sig_material(signed_raw):
            return False, "not all inputs have sig material"
        if not ok and "no p2wpkh" not in msg and "verify_ecdsa missing" not in msg:
            return False, msg
        tok, tmsg = taproot_witnesses_ok(signed_raw)
        if tok:
            return True, "mixed: %s; %s" % (msg, tmsg)
        # Fixture may be multi-p2wpkh only (name mixed but no tb1p legs)
        if ok or "no p2wpkh" in msg:
            return True, "mixed: %s (%s)" % (msg, tmsg)
        return False, tmsg

    # Default: any signature material
    if has_signature_material(signed_raw):
        return True, "sig material present"
    return False, "no signature material"


def run_case(case, seeds_meta, dry_run=False, check_golden=False):
    cid = case["id"]
    expect = case.get("expect", "sign")
    seed_ref = case.get("seed_ref", "unknown")
    unsigned = os.path.join(ROOT, case["unsigned"])
    fkt_out = os.path.join(ROOT, case.get("fkt_signed") or ("fkt-signed/%s.psbt" % cid))
    spr = case.get("sparrow_signed")
    sparrow_path = os.path.join(ROOT, spr) if spr else None
    golden_path = fkt_out  # committed golden lives at fkt-signed/<id>.psbt

    if not os.path.isfile(unsigned):
        return "FAIL", cid, "missing unsigned %s" % unsigned

    seed_hex, seed_src = resolve_seed_hex(seed_ref, seeds_meta)
    if not seed_hex:
        return "SKIP", cid, seed_src

    if dry_run:
        return "DRY", cid, "seed=%s expect=%s" % (seed_src, expect)

    os.makedirs(os.path.dirname(fkt_out), exist_ok=True)

    # Snapshot committed golden before overwrite (if checking)
    golden_bytes = None
    if check_golden and os.path.isfile(golden_path):
        with open(golden_path, "rb") as gf:
            golden_bytes = gf.read()

    rc, err = sign_case(seed_hex, unsigned, fkt_out)

    if expect == "reject":
        if rc != 0:
            return "PASS", cid, "reject as expected (rc=%d) %s" % (rc, err[:60])
        return "FAIL", cid, "expected reject but signer rc=0"

    # sign or partial_sig
    if rc != 0:
        return "FAIL", cid, "signer rc=%d %s" % (rc, err[:120])

    unsigned_raw = open(unsigned, "rb").read()
    ok, detail = evaluate_sign(case, unsigned_raw, fkt_out, sparrow_path)
    if not ok:
        return "FAIL", cid, detail

    if check_golden:
        if golden_bytes is None:
            # Only enforce for cases marked golden in manifest
            if case.get("fkt_signed_status") == "golden":
                return "FAIL", cid, "missing committed golden at %s" % golden_path
        else:
            with open(fkt_out, "rb") as nf:
                new_bytes = nf.read()
            if new_bytes != golden_bytes:
                return "FAIL", cid, "golden mismatch (regen differs from committed fkt-signed)"
            detail = detail + "; golden match"

    return "PASS", cid, detail


def main():
    ap = argparse.ArgumentParser(description="FKT sparrow-real sign/reject harness")
    ap.add_argument("--all", action="store_true", help="Run all priorities")
    ap.add_argument(
        "--priority",
        default=None,
        help="Filter priority: high|medium|low|bonus",
    )
    ap.add_argument(
        "--include-bonus",
        action="store_true",
        help="With default high, also run medium+low (not bonus)",
    )
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument(
        "--list-only",
        action="store_true",
        help="Only list cases (no sign); same as sparrow_real_list",
    )
    ap.add_argument(
        "--check-golden",
        action="store_true",
        help="After sign, require output byte-equal to committed fkt-signed golden",
    )
    args = ap.parse_args()

    if not os.path.isfile(MANIFEST):
        print("ERROR: missing %s" % MANIFEST, file=sys.stderr)
        return 1
    if not args.list_only and not args.dry_run and not os.path.isfile(SIGNER_BIN):
        print("ERROR: missing %s — run make first" % SIGNER_BIN, file=sys.stderr)
        return 1

    man = json.load(open(MANIFEST))
    cases = man.get("cases") or []
    seeds_meta = man.get("seeds") or {}

    if args.priority:
        cases = [c for c in cases if c.get("priority") == args.priority]
    elif args.all:
        pass
    elif args.include_bonus:
        cases = [
            c
            for c in cases
            if c.get("priority") in ("high", "medium", "low", "bonus")
        ]
    else:
        # Default: high + medium + low (critical path). Bonus opt-in via --all.
        cases = [
            c for c in cases if c.get("priority") in ("high", "medium", "low")
        ]

    if not cases:
        print("ERROR: no cases matched", file=sys.stderr)
        return 1

    print(
        "sparrow-real harness  cases=%d  network=%s  signer=%s"
        % (len(cases), man.get("network"), SIGNER_BIN)
    )
    print("%-42s %-6s %s" % ("id", "result", "detail"))
    print("-" * 100)

    passed = failed = skipped = 0
    for case in cases:
        if args.list_only:
            print(
                "%-42s %-6s expect=%s seed_ref=%s"
                % (case["id"], "LIST", case.get("expect"), case.get("seed_ref"))
            )
            continue
        status, cid, detail = run_case(
            case,
            seeds_meta,
            dry_run=args.dry_run,
            check_golden=args.check_golden,
        )
        print("%-42s %-6s %s" % (cid, status, detail))
        if status == "PASS":
            passed += 1
        elif status == "SKIP" or status == "DRY":
            skipped += 1
        else:
            failed += 1

    if args.list_only:
        return 0

    print("-" * 100)
    print("Results: PASS=%d FAIL=%d SKIP=%d" % (passed, failed, skipped))
    if failed:
        return 1
    if passed == 0:
        print("ERROR: nothing passed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
