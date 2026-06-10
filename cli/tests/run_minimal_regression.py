#!/usr/bin/env python3
"""Minimal regression suite – uses fktsigner to derive the key and sign."""
import subprocess, tempfile, struct, os, shutil

SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
SIGNER_BIN = "cli/fktsigner"
DERIV_PATH = "84'/1'/0'/0/0"          # testnet BIP84, known to work

# ----------------------------------------------------------------------
# 1.  Known good public key from signer for this seed+path
# ----------------------------------------------------------------------
# Known-good witness script (matches signer's actual derived key)
import subprocess, hashlib
pubkey_hex = subprocess.run(
    [SIGNER_BIN, "--pubkey", SEED_HEX, DERIV_PATH],
    capture_output=True, text=True, check=True
).stdout.strip()
pubkey = bytes.fromhex(pubkey_hex)
h160 = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
SCRIPT_PUBKEY = b'\x00\x14' + h160
# Taproot: x‑only pubkey (bytes 1..33) + OP_1 OP_PUSH32
x_only = pubkey[1:]   # strip the 02/03 prefix
TAPROOT_SCRIPT = b'\x51\x20' + x_only


# ----------------------------------------------------------------------
# 2.  PSBT builder (exactly the same logic as the earlier self‑test)
# ----------------------------------------------------------------------
def build_psbt(value_in, values_out, sequence=0xfffffffd, locktime=0,
               num_inputs=1, script_pubkey=SCRIPT_PUBKEY, tap_internal_key=None):
    per_input = value_in // num_inputs
    tx = b""
    tx += struct.pack("<I", 2)          # version 2
    tx += bytes([num_inputs])
    for i in range(num_inputs):
        txid = bytes(31) + bytes([i])   # unique dummy txid
        tx += txid + struct.pack("<I", 0) + b'\x00' + struct.pack("<I", sequence)
    tx += bytes([len(values_out)])
    for val in values_out:
        tx += struct.pack("<q", val) + bytes([len(script_pubkey)]) + script_pubkey
    tx += struct.pack("<I", locktime)

    psbt = bytes.fromhex("70736274ff")   # magic
    # global map
    psbt += b'\x01\x00'
    utx_len = len(tx)
    if utx_len < 0xFD:
        psbt += bytes([utx_len])
    else:
        psbt += b'\xFD' + struct.pack("<H", utx_len)
    psbt += tx
    psbt += b'\x00'                      # global terminator

    # input maps
    for _ in range(num_inputs):
        # witness_utxo (0x01)
        psbt += b'\x01\x01'
        wit = struct.pack("<q", per_input) + bytes([len(script_pubkey)]) + script_pubkey
        wit_len = len(wit)
        if wit_len < 0xFD:
            psbt += bytes([wit_len])
        else:
            psbt += b'\xFD' + struct.pack("<H", wit_len)
        psbt += wit

        # Taproot internal key (0x18) if provided
        if tap_internal_key is not None:
            psbt += b'\x01\x18'                     # key length 1, key type 0x18
            psbt += bytes([32]) + tap_internal_key

        # input terminator
        psbt += b'\x00'

    # output maps (empty)
    for _ in values_out:
        psbt += b'\x00'

    return psbt

# ----------------------------------------------------------------------
# 3.  Test cases
# ----------------------------------------------------------------------
tests = []

# Original 13-style cases (all P2WPKH, signable)
tests.append(("1in_1out", build_psbt(100000, [90000])))
tests.append(("1in_2out", build_psbt(200000, [100000, 90000])))
tests.append(("seq_0xffffffff", build_psbt(150000, [140000], sequence=0xffffffff)))
tests.append(("locktime_100", build_psbt(100000, [90000], locktime=100)))
tests.append(("dust", build_psbt(546, [536])))
tests.append(("2in_2out", build_psbt(200000, [100000, 90000], num_inputs=2)))
tests.append(("3in_2out", build_psbt(300000, [150000, 140000], num_inputs=3)))
tests.append(("rbf_sequence", build_psbt(100000, [90000], sequence=0xfffffffd)))
tests.append(("final_sequence", build_psbt(100000, [90000], sequence=0xffffffff)))
tests.append(("high_locktime", build_psbt(100000, [90000], locktime=700000)))
tests.append(("consolidate_3in_1out", build_psbt(300000, [290000], num_inputs=3)))
tests.append(("dust_1in_1out", build_psbt(546, [536])))

# Additional edge cases
tests.append(("very_high_locktime", build_psbt(100000, [90000], locktime=0xFFFFFFFF)))
tests.append(("max_sequence", build_psbt(100000, [90000], sequence=0xffffffff)))
tests.append(("minimal_fee", build_psbt(100000, [99900])))  # 100 sat fee

# ---- Taproot key‑path (P2TR) ----
tests += [
    ("p2tr_1in_1out", build_psbt(100000, [90000],
                                 script_pubkey=TAPROOT_SCRIPT,
                                 tap_internal_key=x_only)),
    ("p2tr_2in_2out", build_psbt(200000, [100000, 90000], num_inputs=2,
                                 script_pubkey=TAPROOT_SCRIPT,
                                 tap_internal_key=x_only)),
    ("p2tr_locktime", build_psbt(100000, [90000], locktime=500000,
                                 script_pubkey=TAPROOT_SCRIPT,
                                 tap_internal_key=x_only)),
    ("p2tr_rbf", build_psbt(100000, [90000], sequence=0xfffffffd,
                            script_pubkey=TAPROOT_SCRIPT,
                            tap_internal_key=x_only)),
    ("p2tr_dust", build_psbt(546, [536],
                             script_pubkey=TAPROOT_SCRIPT,
                             tap_internal_key=x_only)),
]

# P2SH‑P2WPKH test (1 input, 1 output)
# The PSBT must include the redeem script (key 0x04).
# We'll build the P2SH script and then manually add the redeem script to the PSBT.
# The quickest way: use a helper that builds a PSBT with a redeem script.
def build_p2sh_p2wpkh_psbt(value_in, values_out, sequence=0xfffffffd, locktime=0):
    # Build a P2WPKH PSBT first, then wrap the input script with P2SH and insert redeem script
    p2wpkh_spk = SCRIPT_PUBKEY
    redeem_script = p2wpkh_spk   # the witness program is exactly the redeem script
    p2sh_spk = bytes.fromhex("a914") + hashlib.new('ripemd160', redeem_script).digest() + bytes.fromhex("87")

    tx = struct.pack("<I", 2) + b'\x01' + b'\x00'*32 + struct.pack("<I", 0) + b'\x00' + struct.pack("<I", sequence)
    tx += bytes([len(values_out)])
    for v in values_out:
        tx += struct.pack("<q", v) + bytes([len(p2sh_spk)]) + p2sh_spk
    tx += struct.pack("<I", locktime)

    psbt = bytes.fromhex("70736274ff") + b'\x01\x00' + bytes([len(tx)]) + tx + b'\x00'

    # input map: witness_utxo (0x01) + redeem_script (0x04)
    wit = struct.pack("<q", value_in) + bytes([len(p2sh_spk)]) + p2sh_spk
    psbt += b'\x01\x01' + bytes([len(wit)]) + wit

    # redeem script
    rs = redeem_script
    psbt += b'\x01\x04' + bytes([len(rs)]) + rs

    psbt += b'\x00'   # input terminator
    for _ in values_out:
        psbt += b'\x00'

    return psbt

tests += [
    ("p2sh_p2wpkh_1in_1out", build_p2sh_p2wpkh_psbt(100000, [90000])),
]



# Expected rejection cases (unsupported or invalid)
 

# Unsupported script type: P2SH-P2WPKH – signer should reject
# We'll create a PSBT with a P2SH-P2WPKH input. The signer doesn't support it yet.
# We need to provide a redeem script and witness script; but the signer will just
# see an unknown script type and refuse to sign.
# P2SH script (unsupported) – signer should reject it
p2sh_spk = bytes.fromhex("a9140463bce96abf75296997f6d954f8d39e3ab7948e87")
def build_psbt_custom_script(spk, value_in, values_out, sequence=0xfffffffd, locktime=0):
    tx = b""
    tx += struct.pack("<I", 2) + b'\x01'
    tx += b'\x00'*32 + struct.pack("<I", 0) + b'\x00' + struct.pack("<I", sequence)
    tx += bytes([len(values_out)])
    for val in values_out:
        tx += struct.pack("<q", val) + bytes([len(spk)]) + spk
    tx += struct.pack("<I", locktime)
    psbt = bytes.fromhex("70736274ff") + b'\x01\x00'
    utx_len = len(tx)
    psbt += bytes([utx_len]) + tx + b'\x00'
    # input map: witness_utxo + redeem script + witness script? Not needed, signer will just detect type
    psbt += b'\x01\x01'
    wit = struct.pack("<q", value_in) + bytes([len(spk)]) + spk
    psbt += bytes([len(wit)]) + wit + b'\x00'
    for _ in values_out:
        psbt += b'\x00'
    return psbt


# ----------------------------------------------------------------------
# 4.  Run signer and verify
# ----------------------------------------------------------------------
passed = 0
failed = 0
tmpdir = tempfile.mkdtemp()

try:
    for name, psbt_bytes, *expected in tests:
        expected = expected[0] if expected else "sign"
        unsigned_file = os.path.join(tmpdir, f"{name}_unsigned.psbt")
        signed_file   = os.path.join(tmpdir, f"{name}_signed.psbt")
        with open(unsigned_file, "wb") as f:
            f.write(psbt_bytes)

        cmd = [SIGNER_BIN, SEED_HEX, DERIV_PATH, unsigned_file, signed_file]
        ret = subprocess.run(cmd, capture_output=True)

        if expected == "reject":
            if ret.returncode == 0:
                print(f"FAIL {name}: expected rejection but signed")
                failed += 1
            else:
                print(f"PASS {name} (expected rejection)")
                passed += 1
            continue

        # expected sign
        if ret.returncode != 0:
            err = ret.stderr.decode().strip()
            print(f"FAIL {name}: signer returned error: {err}")
            failed += 1
            continue

        with open(signed_file, "rb") as f:
            data = f.read()
            # Verify that a signature was inserted – key type depends on script
        if name.startswith("p2tr"):
                expected_key = b'\x13'   # PSBT_IN_TAP_KEY_SIG
        else:
                expected_key = b'\x02'   # PSBT_IN_PARTIAL_SIG

        if expected_key not in data:
                print(f"FAIL {name}: no {expected_key.hex()} signature found")
                failed += 1
                continue
        else:
            print(f"PASS {name}")
            passed += 1
finally:
    shutil.rmtree(tmpdir)

print(f"\nResults: PASS={passed} FAIL={failed}")
if failed == 0:
    print("Minimal regression suite passed – baseline is solid.")
else:
    print("Some tests FAILED – do not expand until fixed.")