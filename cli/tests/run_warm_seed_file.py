#!/usr/bin/env python3
"""Phase 2 — Warm encrypted seed file round-trip + sign."""
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
SEED = (
    "call release rib regret puzzle magic economy tragic various "
    "embody give road"
)
PASS = "ritual-passphrase-not-for-mainnet"


def run(args, env=None):
    e = os.environ.copy()
    e["FKT_NO_CONFIRM"] = "1"
    if env:
        e.update(env)
    p = subprocess.Popen(
        args,
        cwd=CLI_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=e,
    )
    out, err = p.communicate()
    return (
        p.returncode,
        out.decode("utf-8", "replace"),
        err.decode("utf-8", "replace"),
    )


def main():
    if not os.path.isfile(BIN):
        print("missing fktsigner — make warm first", file=sys.stderr)
        return 1
    # Must be warm build
    rc, out, err = run([BIN, "--version"])
    if rc != 0:
        print("version failed", err)
        return 1

    tmp = tempfile.mkdtemp(prefix="fkt-warm-")
    seed_path = os.path.join(tmp, "ritual.fkt")
    out_psbt = os.path.join(tmp, "signed.psbt")
    settings = os.path.join(tmp, "fkt-warm.conf")
    failed = 0

    def check(name, ok, detail=""):
        print("%-40s %s  %s" % (name, "PASS" if ok else "FAIL", detail))
        return 0 if ok else 1

    # save-seed with passphrase
    rc, out, err = run(
        [
            BIN,
            "save-seed",
            "--out",
            seed_path,
            "--seed",
            SEED,
            "--passphrase",
            PASS,
        ]
    )
    failed += check(
        "save_seed_passphrase",
        rc == 0 and os.path.isfile(seed_path) and os.path.getsize(seed_path) > 40,
        "rc=%s size=%s" % (rc, os.path.getsize(seed_path) if os.path.isfile(seed_path) else 0),
    )
    if rc != 0:
        print(err[:400], file=sys.stderr)

    # magic
    raw = open(seed_path, "rb").read(8) if os.path.isfile(seed_path) else b""
    failed += check("seed_file_magic", raw == b"FKTSEED1", repr(raw))

    # wrong passphrase must fail
    rc, out, err = run(
        [
            BIN,
            "sign",
            "--psbt",
            UNSIGNED,
            "--out",
            out_psbt + ".bad",
            "--seed-file",
            seed_path,
            "--passphrase",
            "wrong",
            "--yes",
        ]
    )
    failed += check("wrong_passphrase_rejects", rc != 0, "rc=%s" % rc)

    # correct passphrase signs
    rc, out, err = run(
        [
            BIN,
            "sign",
            "--psbt",
            UNSIGNED,
            "--out",
            out_psbt,
            "--seed-file",
            seed_path,
            "--passphrase",
            PASS,
            "--yes",
        ]
    )
    failed += check(
        "sign_seed_file",
        rc == 0 and os.path.isfile(out_psbt) and os.path.getsize(out_psbt) > 0,
        "rc=%s" % rc,
    )
    if rc != 0:
        print(err[:500], file=sys.stderr)

    # empty-passphrase save + load
    seed2 = os.path.join(tmp, "empty.fkt")
    rc, out, err = run(
        [BIN, "save-seed", "--out", seed2, "--seed", SEED, "--passphrase", ""]
    )
    # empty pass may be omitted; try without flag
    if rc != 0:
        rc, out, err = run([BIN, "save-seed", "--out", seed2, "--seed", SEED])
    failed += check("save_seed_empty_pass", rc == 0 and os.path.isfile(seed2), "rc=%s" % rc)

    out2 = os.path.join(tmp, "signed2.psbt")
    rc, out, err = run(
        [
            BIN,
            "sign",
            "--psbt",
            UNSIGNED,
            "--out",
            out2,
            "--seed-file",
            seed2,
            "--yes",
        ]
    )
    failed += check("sign_empty_pass_file", rc == 0 and os.path.isfile(out2), "rc=%s" % rc)

    # set-autoload + env settings
    rc, out, err = run([BIN, "set-autoload", seed_path], env={"FKT_WARM_SETTINGS": settings})
    failed += check("set_autoload", rc == 0 and os.path.isfile(settings), "rc=%s" % rc)
    if os.path.isfile(settings):
        conf = open(settings).read()
        failed += check("autoload_line", "autoload_seed=" in conf, conf[:80].replace("\n", " "))

    # Ice Cold build must not accept --seed-file (optional check if dual binaries)
    # Here we only test warm binary.

    print("-" * 60)
    if failed:
        print("Warm seed-file: FAIL (%d)" % failed)
        return 1
    print("Warm seed-file: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
