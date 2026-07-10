#!/usr/bin/env python3
"""Silent Payments signing-path stub (Phase 1 Step 4).

Ice Cold CLI does **not** implement BIP352 scan/spend or SP-specific sighash.
This gate locks that boundary so we do not silently claim support:

  1. Source audit: no SP spend/scan symbols in signer/psbt modules.
  2. Optional: proprietary 0xFC bark/SP-shaped keys still pass through (covered
     by test-proprietary); this stub only asserts the SP path is deferred.

PASS = stub documented + boundary held. Real SP lands with PWA/relay later.
"""
from __future__ import print_function

import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CLI_DIR = os.path.join(SCRIPT_DIR, "..")

# Symbols / APIs that would mean we claimed SP signing support.
FORBIDDEN = [
    r"fkt_silent_payment",
    r"bip352",
    r"BIP352",
    r"silent_payment_scan",
    r"silent_payment_spend",
    r"sp_ecdh",
]

SCAN_FILES = [
    "fkt_signer.c",
    "fkt_signer.h",
    "fkt_psbt.c",
    "fkt_psbt.h",
    "fkt_sighash.c",
    "fkt_finalizer.c",
    "main.c",
]


def main():
    hits = []
    for name in SCAN_FILES:
        path = os.path.join(CLI_DIR, name)
        if not os.path.isfile(path):
            print("FAIL  missing %s" % name)
            return 1
        text = open(path, "rb").read().decode("utf-8", "replace")
        for pat in FORBIDDEN:
            if re.search(pat, text, re.IGNORECASE):
                hits.append("%s ~ /%s/" % (name, pat))

    if hits:
        print("FAIL  unexpected Silent Payments signing symbols:")
        for h in hits:
            print("  ", h)
        return 1

    print("PASS  no SP scan/spend API in Ice Cold signer modules")
    print("PASS  Silent Payments signing path = deferred stub (PWA/relay later)")
    print("Note: proprietary 0xFC passthrough (bark/SP metadata) is separate —")
    print("      covered by make test-proprietary / p2wpkh_proprietary_passthrough")
    print("Results: PASS=2 FAIL=0 (stub)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
