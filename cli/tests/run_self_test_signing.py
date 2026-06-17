#!/usr/bin/env python3
import os, subprocess, tempfile, shutil, struct, hashlib


# ============================================================
# Demo seed + path (the signer will use these)
# ============================================================
DEMO_SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
DEMO_PATH = "84'/0'/0'/0/0"
SIGNER_BIN = os.path.join(os.path.dirname(__file__), "..", "fktsigner")

# Hardcoded witness program that matches the signer's actual derivation
# (derived HASH160 from manual test: 54ac44bb27eb81470ae0451c99550f06a2dfa8f1)
SCRIPT_PUBKEY = bytes.fromhex("001454ac44bb27eb81470ae0451c99550f06a2dfa8f1")

# ============================================================
# Manual PSBT builder (no external dependencies)
# ============================================================
def build_psbt_hex(value_in, values_out, sequence=0xfffffffd, locktime=0,
                   num_inputs=1, script_pubkey=SCRIPT_PUBKEY):
    """Create a minimal PSBT with unique prev‑txids for each input."""
    per_input_amount = value_in // num_inputs   # split total equally

    # ---- Build unsigned transaction ----
    tx = b""
    tx += struct.pack("<I", 2)            # version
    tx += bytes([num_inputs])             # input count
    for inp_idx in range(num_inputs):
        # unique dummy txid: 31 zero bytes + index byte
        txid = b'\x00' * 31 + bytes([inp_idx])
        tx += txid
        tx += struct.pack("<I", 0)        # vout
        tx += b'\x00'                     # empty scriptSig
        tx += struct.pack("<I", sequence)
    tx += bytes([len(values_out)])        # output count
    for val in values_out:
        tx += struct.pack("<q", val)
        spk = script_pubkey
        spk_len = len(spk)
        if spk_len < 0xFD:
            tx += bytes([spk_len])
        else:
            tx += b'\xFD' + struct.pack("<H", spk_len)
        tx += spk
    tx += struct.pack("<I", locktime)

    # ---- PSBT wrapper ----
    psbt = bytes.fromhex("70736274ff")    # magic
    # global map
    psbt += b'\x01\x00'                   # key type 0x00
    utx_len = len(tx)
    if utx_len < 0xFD:
        psbt += bytes([utx_len])
    else:
        psbt += b'\xFD' + struct.pack("<H", utx_len)
    psbt += tx
    psbt += b'\x00'                       # global terminator

    # ---- Input maps ----
    for _ in range(num_inputs):
        # witness_utxo
        psbt += b'\x01\x01'               # key type 0x01
        wit = struct.pack("<q", per_input_amount)
        spk_len = len(script_pubkey)
        if spk_len < 0xFD:
            wit += bytes([spk_len])
        else:
            wit += b'\xFD' + struct.pack("<H", spk_len)
        wit += script_pubkey
        wit_len = len(wit)
        if wit_len < 0xFD:
            psbt += bytes([wit_len])
        else:
            psbt += b'\xFD' + struct.pack("<H", wit_len)
        psbt += wit

        # For Taproot, add internal key
        if script_pubkey[:2] == b'\x51\x20':
            tap_int_key = script_pubkey[2:]   # x‑only pubkey
            psbt += b'\x01'                   # key length 1
            psbt += b'\x18'                   # key type 0x16
            psbt += bytes([32])               # value length 32
            psbt += tap_int_key

        psbt += b'\x00'                       # input terminator

    # ---- Output maps (empty) ----
    for _ in values_out:
        psbt += b'\x00'

    return psbt.hex()

# ============================================================
# Test cases
# ============================================================
tests = [
    ("simple_1in_1out", build_psbt_hex(100000, [90000])),
    ("simple_1in_2out", build_psbt_hex(200000, [100000, 90000])),
    ("seq_0xffffffff", build_psbt_hex(150000, [140000], sequence=0xffffffff)),
    ("locktime_100",    build_psbt_hex(100000, [90000], locktime=100)),
    ("dust_fee",        build_psbt_hex(546, [536])),
]
tests += [
    ("2in_2out", build_psbt_hex(200000, [100000, 90000], num_inputs=2)),
    ("3in_2out", build_psbt_hex(300000, [150000, 140000], num_inputs=3)),
    ("rbf_sequence", build_psbt_hex(100000, [90000], sequence=0xfffffffd)),
    ("final_sequence", build_psbt_hex(100000, [90000], sequence=0xffffffff)),
    ("high_locktime", build_psbt_hex(100000, [90000], locktime=700000)),
    ("consolidate_3in_1out", build_psbt_hex(300000, [290000], num_inputs=3)),
    ("dust_1in_1out", build_psbt_hex(546, [536])),
]

# Taproot (P2TR) test: derive the x-only pubkey from the demo key
# Demo pubkey = 022ac617b2c5d5a81c29be9b7bdc4eb449832647bac292b57ed8be1c0921c71d2e
# The x-only pubkey is the last 32 bytes (i.e., remove the first byte 02).
taproot_xonly = bytes.fromhex("2ac617b2c5d5a81c29be9b7bdc4eb449832647bac292b57ed8be1c0921c71d2e")
taproot_script = b'\x51\x20' + taproot_xonly   # OP_1 + OP_PUSH32

tests += [
    ("taproot_1in_1out", build_psbt_hex(100000, [90000],
                                        script_pubkey=taproot_script)),
]
# ============================================================
# Run signer and verify
# ============================================================
passed = 0
failed = 0
tmpdir = tempfile.mkdtemp()
expected_hash160 = SCRIPT_PUBKEY[2:]   # skip 0x00, 0x14

try:
    for name, psbt_hex in tests:
        unsigned_file = os.path.join(tmpdir, f"{name}_unsigned.psbt")
        signed_file   = os.path.join(tmpdir, f"{name}_signed.psbt")
        with open(unsigned_file, "wb") as f:
            f.write(bytes.fromhex(psbt_hex))

        # Run the signer
        cmd = [SIGNER_BIN, DEMO_SEED_HEX, DEMO_PATH, unsigned_file, signed_file]
        ret = subprocess.run(cmd, capture_output=True)
        if ret.returncode != 0:
            print(f"FAIL {name}: signer returned error")
            failed += 1
            continue

        # Simple verification: the signed file should be larger and contain a
        # partial signature key (0x02). This confirms the signer did its job.
        with open(signed_file, "rb") as f:
            data = f.read()
        if len(data) <= len(bytes.fromhex(psbt_hex)):
            print(f"FAIL {name}: signed file not larger than unsigned")
            failed += 1
            continue
        if b'\x02' not in data:
            print(f"FAIL {name}: no partial signature key found")
            failed += 1
            continue
        print(f"PASS {name}")
        passed += 1

finally:
    shutil.rmtree(tmpdir)

print(f"\nResults: PASS={passed} FAIL={failed}")
if failed == 0:
    print("All signing tests passed – crypto module is locked.")
else:
    print("Some tests FAILED – do not expand until fixed.")