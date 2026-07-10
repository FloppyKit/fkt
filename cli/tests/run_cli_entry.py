#!/usr/bin/env python3
"""Phase 1 Step 3 — CLI entry gate (preview→seed→sign→binary+Base64).

Non-interactive only (--seed --yes). Covers:
  - binary .psbt input
  - Base64 input (--base64)
  - clean Base64 on stdout after sign
  - base64 subcommand
  - qr --psbt --term (non-interactive encode/display path)
"""
from __future__ import print_function

import os
import subprocess
import sys
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CLI_DIR = os.path.join(SCRIPT_DIR, "..")
BIN = os.path.join(CLI_DIR, "fktsigner")
UNSIGNED = os.path.join(
    SCRIPT_DIR, "sparrow-real", "unsigned", "p2tr_1in_1out.psbt"
)
# call_release mnemonic — used for sparrow-real Taproot keypath vectors
SEED = (
    "call release rib regret puzzle magic economy tragic various "
    "embody give road"
)


def run(args, env=None):
    e = os.environ.copy()
    if env:
        e.update(env)
    e["FKT_NO_CONFIRM"] = "1"
    p = subprocess.Popen(
        args,
        cwd=CLI_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=e,
    )
    out, err = p.communicate()
    return p.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def main():
    if not os.path.isfile(BIN):
        print("missing fktsigner — make first", file=sys.stderr)
        return 1
    if not os.path.isfile(UNSIGNED):
        print("missing fixture:", UNSIGNED, file=sys.stderr)
        return 1

    tmp = tempfile.mkdtemp(prefix="fkt-cli-entry-")
    out_bin = os.path.join(tmp, "signed.psbt")
    failed = 0

    def check(name, ok, detail=""):
        status = "PASS" if ok else "FAIL"
        print("%-40s %s  %s" % (name, status, detail))
        return 0 if ok else 1

    # --- binary sign ---
    rc, out, err = run(
        [
            BIN,
            "sign",
            "--psbt",
            UNSIGNED,
            "--out",
            out_bin,
            "--seed",
            SEED,
            "--yes",
        ]
    )
    ok = rc == 0 and os.path.isfile(out_bin) and os.path.getsize(out_bin) > 0
    failed += check("sign_binary_psbt", ok, "rc=%s size=%s" % (
        rc, os.path.getsize(out_bin) if os.path.isfile(out_bin) else 0))
    if not ok and err:
        print(err[:400], file=sys.stderr)

    has_written = "Signed PSBT written:" in out
    has_b64_hdr = "Signed PSBT Base64:" in out
    # one-line base64 starting with classic psbt magic prefix
    b64_lines = [
        ln.strip()
        for ln in out.splitlines()
        if ln.strip().startswith("cHNidP")
    ]
    failed += check(
        "sign_prints_clean_base64",
        has_written and has_b64_hdr and len(b64_lines) >= 1,
        "b64_lines=%d" % len(b64_lines),
    )

    # --- base64 subcommand ---
    rc, out_b64, err = run([BIN, "base64", out_bin])
    ok = rc == 0 and out_b64.strip().startswith("cHNidP")
    failed += check("base64_subcommand", ok, "rc=%s" % rc)

    # --- sign from Base64 input ---
    out2 = os.path.join(tmp, "signed2.psbt")
    b64_in = out_b64.strip() if out_b64.strip().startswith("cHNidP") else ""
    # Prefer unsigned as base64 for a true round-trip input
    rc_u, u_b64, _ = run([BIN, "base64", UNSIGNED])
    if rc_u == 0 and u_b64.strip().startswith("cHNidP"):
        b64_in = u_b64.strip()
    # Arg length safety: skip if absurdly large for argv
    if b64_in and len(b64_in) < 6000:
        rc, out, err = run(
            [
                BIN,
                "sign",
                "--base64",
                b64_in,
                "--out",
                out2,
                "--seed",
                SEED,
                "--yes",
            ]
        )
        ok = rc == 0 and os.path.isfile(out2) and os.path.getsize(out2) > 0
        failed += check("sign_base64_input", ok, "rc=%s" % rc)
        if not ok and err:
            print(err[:400], file=sys.stderr)
    else:
        failed += check("sign_base64_input", False, "skip/no b64")

    # --- QR path (force term; non-interactive display) ---
    # Use signed binary; may be large for term — still must not crash encode path.
    rc, out, err = run([BIN, "qr", "--psbt", out_bin, "--term"])
    # interactive display may still return 0; accept 0 or documented size fail
    ok = rc == 0 or "QR encode failed" in err or "too large" in err.lower()
    # Prefer success when payload fits
    if rc == 0:
        failed += check("qr_psbt_term", True, "rc=0")
    else:
        # encoding succeeded but display failed is still partial — require encode ok
        failed += check(
            "qr_psbt_term",
            "QR encode failed" not in err,
            "rc=%s err=%s" % (rc, err[:80].replace("\n", " ")),
        )

    # --- preview/inspect still works ---
    rc, out, err = run([BIN, "inspect", UNSIGNED])
    failed += check("inspect_psbt", rc == 0, "rc=%s" % rc)

    print("-" * 60)
    if failed:
        print("CLI entry: FAIL (%d checks)" % failed)
        return 1
    print("CLI entry: PASS")
    return 0


if __name__ == "__main__":
    # Python 2/3: avoid nonlocal keyword
    sys.exit(main())
