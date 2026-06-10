#!/usr/bin/env python3
import os, sys, json, hashlib, struct

sys.path.insert(0, os.path.dirname(__file__))

from lib.signer import get_pubkey
from lib.builder import build_psbt, p2wpkh_script, p2tr_script, p2sh_p2wpkh_script

MANIFEST = "manifest.json"
UNSIGNED_DIR = "unsigned"

from configs import v1
all_cases = v1.cases

os.makedirs(UNSIGNED_DIR, exist_ok=True)

pubkey_hex = get_pubkey()
pubkey = bytes.fromhex(pubkey_hex)
xonly = pubkey[1:]

script_builders = {
    "p2wpkh": lambda: p2wpkh_script(pubkey),
    "p2tr": lambda: p2tr_script(pubkey),
    "p2sh_p2wpkh": lambda: p2sh_p2wpkh_script(pubkey),
}

manifest = []
for c in all_cases:
    name = c["name"]
    expected = c["expected"]

    if c.get("script_override"):
        spk = bytes.fromhex("a9140463bce96abf75296997f6d954f8d39e3ab7948e87")
        tap_key = None
        redeem = None
    else:
        script_fn = script_builders[c["script"]]
        spk = script_fn()
        tap_key = xonly if c["script"] == "p2tr" else None
        # P2SH‑P2WPKH: redeem script is the P2WPKH witness program, NOT the P2SH script
        if c["script"] == "p2sh_p2wpkh":
            redeem = p2wpkh_script(pubkey)
        else:
            redeem = None

    psbt_bytes = build_psbt(
        value_in=c["value_in"],
        values_out=c["values_out"],
        script_pubkey=spk,
        num_inputs=c.get("num_inputs", 1),
        sequence=c.get("sequence", 0xfffffffd),
        locktime=c.get("locktime", 0),
        tap_internal_key=tap_key,
        redeem_script=redeem,
        duplicate_txid=c.get("duplicate_txid", False),
        sighash=c.get("sighash"),
        unknown_key=c.get("unknown_key")
    )

    filepath = os.path.join(UNSIGNED_DIR, name + ".psbt")
    with open(filepath, "wb") as f:
        f.write(psbt_bytes)

    manifest.append({
        "name": name,
        "expected": expected,
        "file": filepath
    })

with open(MANIFEST, "w") as f:
    json.dump(manifest, f, indent=2)

print(f"Generated {len(manifest)} test vectors in {UNSIGNED_DIR}/")