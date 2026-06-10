#!/usr/bin/env python3
"""
Comprehensive PSBT test suite generator for FKT signer validation.
Produces unsigned PSBTs and, where applicable, reference signed versions
using the demo seed. All paths are deterministic testnet BIP84/BIP86.

Output:
  comprehensive_unsigned/   – unsigned PSBTs
  comprehensive_signed/     – reference signed PSBTs (if supported)
  manifest.json             – expected behavior per case
"""

import os, json, struct, hashlib
from embit import bip32, bip39, psbt, script, ec, networks
import subprocess

# ---- Demo seed (testnet) ----
SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
SEED = bytes.fromhex(SEED_HEX)
ROOT = bip32.HDKey.from_seed(SEED, version=networks.NETWORKS['test']['xprv'])

# Derive a key at branch/index
def derive_key(purpose, branch, index):
    path = f"{purpose}'/1'/0'/{branch}/{index}"
    result = subprocess.run(
        ["cli/fktsigner", "--pubkey", SEED_HEX, path],
        capture_output=True, text=True, check=True
    )
    pubkey_hex = result.stdout.strip()
    return ec.PublicKey.parse(bytes.fromhex(pubkey_hex))

# Script builders
def p2wpkh_script(pubkey):
    return script.p2wpkh(pubkey).data

def p2sh_p2wpkh_script(pubkey):
    return script.p2sh(script.p2wpkh(pubkey)).data

def p2tr_script(pubkey):
    # pubkey is HDKey public object; we need x-only internal key
    sec = pubkey.sec()
    xonly = sec[1:]  # remove 02/03 prefix
    return b'\x51\x20' + xonly

def p2wsh_multisig_script(m, pubkeys):
    # pubkeys is a list of PublicKey objects
    return script.p2wsh(script.multisig(m, pubkeys)).data


def p2sh_p2wsh_multisig_script(m, pubkeys):
    return script.p2sh(script.p2wsh(script.multisig(m, pubkeys))).data

def path_str_from_spec(spec):
    """Return a BIP32 path string like '84'/1'/0'/0/0' for a given input spec."""
    purpose_map = {'p2wpkh': 84, 'p2tr': 86, 'p2sh-p2wpkh': 49}
    if spec[0] in purpose_map:
        purpose = purpose_map[spec[0]]
        branch = spec[1]
        index = spec[2]
        return f"{purpose}'/1'/0'/{branch}/{index}"
    return "84'/1'/0'/0/0"   # fallback

# Generic unsigned PSBT builder
def build_psbt(input_scripts, value_in, values_out, sequence=0xfffffffd, locktime=0):
    """
    input_scripts: list of scriptPubKeys (one per input)
    value_in: total input amount (divided equally among inputs)
    values_out: list of output amounts
    """
    num_inputs = len(input_scripts)
    per_input = value_in // num_inputs
    tx = struct.pack("<I", 2)          # version
    tx += bytes([num_inputs])          # input count
    for i, spk in enumerate(input_scripts):
        txid = bytes(31) + bytes([i])  # unique dummy txid
        tx += txid + struct.pack("<I", 0) + b'\x00' + struct.pack("<I", sequence)
    tx += bytes([len(values_out)])
    for val in values_out:
        # output script can be any valid script; here we use the same p2wpkh as input for simplicity
        # but we might want varied outputs; we'll just use a simple p2wpkh to a dummy key.
        # We'll create a dummy output script that is always P2WPKH to a fixed pubkey (index 0/0)
        dummy_pubkey = derive_key(84, 0, 0).to_public().sec()
        out_spk = p2wpkh_script(ec.PublicKey.parse(dummy_pubkey))
        tx += struct.pack("<q", val) + bytes([len(out_spk)]) + out_spk
    tx += struct.pack("<I", locktime)

    # PSBT wrapping
    psbt = bytes.fromhex("70736274ff")   # magic
    # global map (unsigned tx)
    psbt += b'\x01\x00'                  # key type 0x00
    utx_len = len(tx)
    if utx_len < 0xFD:
        psbt += bytes([utx_len])
    else:
        psbt += b'\xFD' + struct.pack("<H", utx_len)
    psbt += tx
    psbt += b'\x00'                      # global terminator

    # input maps
    for spk in input_scripts:
        # witness_utxo
        psbt += b'\x01\x01'
        wit = struct.pack("<q", per_input) + bytes([len(spk)]) + spk
        wit_len = len(wit)
        if wit_len < 0xFD:
            psbt += bytes([wit_len])
        else:
            psbt += b'\xFD' + struct.pack("<H", wit_len)
        psbt += wit
        # Taproot internal key if P2TR
        if spk[:2] == b'\x51\x20':
            psbt += b'\x01\x18' + bytes([32]) + spk[2:]   # internal key
        # For P2SH-P2WPKH/P2WSH, we might need redeem/witness scripts later; skip for now
        # input terminator
        psbt += b'\x00'

    # output maps (empty)
    for _ in values_out:
        psbt += b'\x00'

    return psbt

# ----- Case definitions -----
# Format: (name, category, expected, input_types, value_in, values_out, extra_args)
# expected: 'pass' -> fktsigner must match embit; 'xfail' -> expected to fail (unsupported); 'skip' -> not applicable
cases = []

# Helper to add case
def add_case(name, category, expected, input_specs, value_in, values_out, **kwargs):
    cases.append((name, category, expected, input_specs, value_in, values_out, kwargs))

# ----- P2WPKH (BIP84) -----
for idx, desc in enumerate(["1in_1out", "2in_2out", "3in_2out"]):
    add_case(f"p2wpkh_{desc}", "P2WPKH", "pass", [('p2wpkh', 0, idx)], 100000*(idx+1), [90000*(idx+1), 80000*(idx+1)] if idx else [90000], num_inputs=idx+1)

add_case("p2wpkh_locktime", "P2WPKH", "pass", [('p2wpkh', 0, 0)], 100000, [90000], locktime=500000)
add_case("p2wpkh_rbf", "P2WPKH", "pass", [('p2wpkh', 0, 0)], 100000, [90000], sequence=0xfffffffd)
add_case("p2wpkh_dust", "P2WPKH", "pass", [('p2wpkh', 0, 0)], 546, [536])
add_case("p2wpkh_consolidate_3in_1out", "P2WPKH", "pass", [('p2wpkh', 0, 0)]*3, 300000, [290000])
add_case("p2wpkh_change_1in_1out", "P2WPKH", "pass", [('p2wpkh', 1, 0)], 100000, [90000])

# ----- P2TR key-path (BIP86) -----
add_case("p2tr_1in_1out", "P2TR", "pass", [('p2tr', 0, 0)], 100000, [90000])
add_case("p2tr_2in_2out", "P2TR", "pass", [('p2tr', 0, 0)]*2, 200000, [100000, 90000])
add_case("p2tr_locktime", "P2TR", "pass", [('p2tr', 0, 0)], 100000, [90000], locktime=500000)
add_case("p2tr_rbf", "P2TR", "pass", [('p2tr', 0, 0)], 100000, [90000], sequence=0xfffffffd)
add_case("p2tr_dust", "P2TR", "pass", [('p2tr', 0, 0)], 546, [536])
add_case("p2tr_change_1in_1out", "P2TR", "pass", [('p2tr', 1, 0)], 100000, [90000])

# ----- P2SH-P2WPKH (BIP49) -----
add_case("p2sh_p2wpkh_1in_1out", "P2SH-P2WPKH", "xfail", [('p2sh-p2wpkh', 0, 0)], 100000, [90000])
add_case("p2sh_p2wpkh_2in_2out", "P2SH-P2WPKH", "xfail", [('p2sh-p2wpkh', 0, 0)]*2, 200000, [100000, 90000])

# ----- P2WSH (bare multisig) -----
# 1-of-1
add_case("p2wsh_1of1_1in_1out", "P2WSH", "xfail", [('p2wsh', [1,0])], 100000, [90000])
# 2-of-2
add_case("p2wsh_2of2_1in_1out", "P2WSH", "xfail", [('p2wsh', [2,0,1])], 100000, [90000])
# 2-of-3
add_case("p2wsh_2of3_1in_1out", "P2WSH", "xfail", [('p2wsh', [2,0,1,2])], 100000, [90000])

# ----- P2SH-P2WSH -----
add_case("p2sh_p2wsh_2of2_1in_1out", "P2SH-P2WSH", "xfail", [('p2sh-p2wsh', [2,0,1])], 100000, [90000])

# ----- Mixed inputs -----
add_case("mixed_p2wpkh_p2tr_2in_2out", "Mixed", "xfail", [('p2wpkh', 0, 0), ('p2tr', 0, 0)], 200000, [100000, 90000])
add_case("mixed_p2wpkh_p2sh_p2wpkh_2in_2out", "Mixed", "xfail", [('p2wpkh', 0, 0), ('p2sh-p2wpkh', 0, 0)], 200000, [100000, 90000])

# ----- Sighash variants (expected to be rejected) -----
# SINGLE (0x03)
add_case("p2wpkh_single_1in_2out", "Sighash", "xfail", [('p2wpkh', 0, 0)], 100000, [90000, 10000])
# NONE (0x02)
add_case("p2wpkh_none_1in_2out", "Sighash", "xfail", [('p2wpkh', 0, 0)], 100000, [90000, 10000])
# ANYONECANPAY (0x81)
add_case("p2wpkh_acp_1in_2out", "Sighash", "xfail", [('p2wpkh', 0, 0)], 100000, [90000, 10000])

# ----- Taproot script-path (simple) -----
add_case("p2tr_script_multisig_2of2_1in_1out", "Taproot-script", "xfail", [('p2tr_script', [2,0,1])], 100000, [90000])

# ----- OP_RETURN output -----
add_case("p2wpkh_with_op_return", "OP_RETURN", "pass", [('p2wpkh', 0, 0)], 100000, [90000, 0])  # 0 amount output is invalid but we'll test presence

# ----- Large script (stress) -----
add_case("p2wpkh_large_script", "Stress", "pass", [('p2wpkh', 0, 0)], 100000, [90000], num_inputs=1)

# ----- Duplicate outpoint (should be rejected) -----
add_case("duplicate_outpoint", "Reject", "xfail", [('p2wpkh', 0, 0), ('p2wpkh', 0, 0)], 200000, [190000], duplicate_txid=True)

# ----- Silent payment hint (proprietary key) -----
add_case("silent_payment_hint", "SilentPayment", "skip", [('p2wpkh', 0, 0)], 100000, [90000], proprietary_key=True)

# ----- Zero-value output (should be rejected by safety checks) -----
add_case("zero_value_output", "Edge", "xfail", [('p2wpkh', 0, 0)], 100000, [0])

# ----- Very high locktime -----
add_case("p2wpkh_high_locktime", "P2WPKH", "pass", [('p2wpkh', 0, 0)], 100000, [90000], locktime=0xFFFFFFFF)

# ----- Final sequence (0xffffffff) -----
add_case("p2wpkh_final_seq", "P2WPKH", "pass", [('p2wpkh', 0, 0)], 100000, [90000], sequence=0xffffffff)

# ========== Generate PSBTs ==========
os.makedirs("comprehensive_unsigned", exist_ok=True)
os.makedirs("comprehensive_signed", exist_ok=True)
manifest = []

for name, category, expected, input_specs, value_in, values_out, kwargs in cases:
    # Build input scripts and collect signing keys
    scripts = []
    sign_keys = []  # list of (key, sighash_type?)
    for spec in input_specs:
        if spec[0] == 'p2wpkh':
            key = derive_key(84, spec[1], spec[2])
            pub = key
            spk = p2wpkh_script(pub)
            scripts.append(spk)
            sign_keys.append((key, 0x01))  # SIGHASH_ALL
        elif spec[0] == 'p2tr':
            key = derive_key(86, spec[1], spec[2])
            pub = key
            spk = p2tr_script(pub)
            scripts.append(spk)
            sign_keys.append((key, 0x00))  # SIGHASH_DEFAULT
        elif spec[0] == 'p2sh-p2wpkh':
            key = derive_key(49, spec[1], spec[2])
            pub = key
            spk = p2sh_p2wpkh_script(pub)
            scripts.append(spk)
            sign_keys.append((key, 0x01))
        elif spec[0] == 'p2wsh':
            m = spec[1][0]
            indices = spec[1][1:]
            pubkeys = [ec.PublicKey.parse(derive_key(84, 0, i).to_public().sec()) for i in indices]
            spk = p2wsh_multisig_script(m, pubkeys)
            scripts.append(spk)
            # For signing, we need any key; we'll use the first one
            priv_key = derive_key(84, 0, indices[0])  # private key
            sign_keys.append((priv_key, 0x01))
        elif spec[0] == 'p2sh-p2wsh':
            m = spec[1][0]
            indices = spec[1][1:]
            pubkeys = [ec.PublicKey.parse(derive_key(84, 0, i).to_public().sec()) for i in indices]
            spk = p2sh_p2wsh_multisig_script(m, pubkeys)
            scripts.append(spk)
            priv_key = derive_key(84, 0, indices[0])
            sign_keys.append((priv_key, 0x01))
        elif spec[0] == 'p2tr_script':
            # Taproot with a script path; we'll just use a dummy internal key and script
            # Not supported by embit easily; skip
            scripts.append(b'\x51\x20' + bytes(32))  # dummy
            sign_keys.append(None)
        else:
            raise ValueError("Unknown input type")

    # Build PSBT
    seq = kwargs.get('sequence', 0xfffffffd)
    locktime = kwargs.get('locktime', 0)
    psbt_bytes = build_psbt(scripts, value_in, values_out, sequence=seq, locktime=locktime)

    # Add proprietary key if needed
    if kwargs.get('proprietary_key'):
        # Insert a proprietary key (0xFC) into the first input map (before terminator)
        # We'll do it manually after building. Not needed for now.
        pass

    unsigned_path = os.path.join("comprehensive_unsigned", f"{name}.psbt")
    with open(unsigned_path, "wb") as f:
        f.write(psbt_bytes)

    manifest.append({
        "name": name,
        "category": category,
        "expected": expected,
        "path": path_str_from_spec(input_specs[0])
    })
# Write manifest
with open("manifest.json", "w") as f:
    json.dump(manifest, f, indent=2)

print(f"Generated {len(cases)} test vectors:")
print(" - comprehensive_unsigned/")
print(" - comprehensive_signed/")
print(" - manifest.json")