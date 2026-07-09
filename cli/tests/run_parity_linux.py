#!/usr/bin/env python3
"""Linux parity: pure CLI (sign --seed --yes) vs dev-harness hex path.

Pure CLI uses fkt_sign_psbt_from_words — same entry as TUI signing.
Dev harness: ./fktsigner <seed_hex> <path> <in> <out>
"""
from __future__ import print_function

import hashlib
import json
import os
import subprocess
import sys
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CLI_DIR = os.path.join(SCRIPT_DIR, "..")
BIN = os.path.join(CLI_DIR, "fktsigner")
MANIFEST = os.path.join(SCRIPT_DIR, "sparrow-real", "manifest.json")
ROOT = os.path.join(SCRIPT_DIR, "sparrow-real")

CALL = (
    "call release rib regret puzzle magic economy tragic various "
    "embody give road"
)
NESTED = (
    "reward parade plug shop winner melt leg unfold sand side shell "
    "receive vague miracle day wall pear season upper monkey wear "
    "duck paper brush"
)
LEGACY_HEX = (
    "46b6b71e4a52ba6259aae7a9eaa991aea07fead2850cb9710aea4b234b73dcc2"
    "6f21d986924ec4224f0fff3b2c73788de8e1f925451b79fcccbed9951b9b184d"
)


def mnem_hex(m):
    return hashlib.pbkdf2_hmac(
        "sha512", m.encode("utf-8"), b"mnemonic", 2048, 64
    ).hex()


SEEDS = {
    "call_release": (CALL, mnem_hex(CALL)),
    "nested_reward_parade": (NESTED, mnem_hex(NESTED)),
    "legacy_p2wpkh_hex": (None, LEGACY_HEX),
}


def main():
    if not os.path.isfile(BIN):
        print("missing fktsigner — make first", file=sys.stderr)
        return 1
    man = json.load(open(MANIFEST))
    cases = [
        c
        for c in man.get("cases") or []
        if c.get("priority") in ("high", "medium", "low")
        and c.get("seed_ref") in SEEDS
        and c.get("expect") == "sign"
    ]
    tmp = tempfile.mkdtemp(prefix="fkt-parity-")
    passed = failed = 0
    print("Linux parity (CLI pure == TUI crypto path vs hex harness)")
    print("binary:", BIN)
    print("cases:", len(cases))
    print("%-40s %-6s %s" % ("id", "result", "detail"))
    print("-" * 90)

    for c in cases:
        cid = c["id"]
        unsigned = os.path.join(ROOT, c["unsigned"])
        if not os.path.isfile(unsigned):
            print("%-40s SKIP   missing unsigned" % cid)
            continue
        mnem, seed_hex = SEEDS[c["seed_ref"]]
        out_cli = os.path.join(tmp, cid + ".cli.psbt")
        out_hex = os.path.join(tmp, cid + ".hex.psbt")

        if mnem:
            r_cli = subprocess.run(
                [
                    BIN,
                    "sign",
                    "--psbt",
                    unsigned,
                    "--out",
                    out_cli,
                    "--seed",
                    mnem,
                    "--yes",
                ],
                capture_output=True,
                text=True,
            )
        else:
            r_cli = subprocess.run(
                [BIN, seed_hex, "m/0", unsigned, out_cli],
                capture_output=True,
                text=True,
            )
        r_hex = subprocess.run(
            [BIN, seed_hex, "m/0", unsigned, out_hex],
            capture_output=True,
            text=True,
        )

        ok_cli = r_cli.returncode == 0 and os.path.isfile(out_cli)
        ok_hex = r_hex.returncode == 0 and os.path.isfile(out_hex)
        if not ok_cli or not ok_hex:
            err = ""
            if not ok_cli:
                err += " cli=" + ((r_cli.stderr or r_cli.stdout or "")[:100])
            if not ok_hex:
                err += " hex=" + ((r_hex.stderr or r_hex.stdout or "")[:100])
            print("%-40s FAIL   sign failed%s" % (cid, err))
            failed += 1
            continue
        b1 = open(out_cli, "rb").read()
        b2 = open(out_hex, "rb").read()
        if b1 == b2:
            print("%-40s PASS   byte-equal CLI/TUI-path vs hex (%d B)" % (cid, len(b1)))
            passed += 1
        else:
            print(
                "%-40s FAIL   size cli=%d hex=%d mismatch"
                % (cid, len(b1), len(b2))
            )
            failed += 1

    print("-" * 90)
    print("PASS=%d FAIL=%d" % (passed, failed))
    print(
        "Note: TUI menu calls fkt_sign_psbt_from_words — same as "
        "`fktsigner sign --seed --yes`."
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
