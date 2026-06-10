#!/usr/bin/env python3
"""
generate_golden_psbts.py
========================

Build the 51-vector unsigned PSBT corpus for the FKT signer test
harness. Output goes into ``unsigned/`` next to this script.

Test seed (BIP-39, English wordlist, no passphrase)::

    call release rib regret puzzle magic economy tragic various embody give road

All UTXOs are synthetic. Previous-tx txids are deterministic SHA256d
hashes of "FKT_GOLDEN_51:<case_name>:<idx>" so re-running the script
always produces byte-identical PSBTs.

Dependencies:
    pip install embit

The script is intentionally written in a flat, table-driven style.
Each ``Case`` row describes one PSBT; the dispatcher in :func:`build`
picks the right builder and writes the file. Adding a case is a one-
line table edit.

Categories
----------
- ``p2wpkh``        : BIP-84 native segwit (V1.0 supported)
- ``p2tr_keypath``  : BIP-86 / BIP-341 key-path (V1.0 supported)
- ``p2sh_p2wpkh``   : BIP-49 wrapped segwit (V1.5 deferred; structural)
- ``p2wsh``         : multisig native (V1.5 deferred; structural)
- ``p2sh_p2wsh``    : multisig wrapped (V1.5 deferred; structural)
- ``mixed``         : mixed input types and edge cases
"""

from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

# --------------------------------------------------------------------------
# Dependency probe. Embit is the only third-party requirement; surface a
# clean error if it's missing.
# --------------------------------------------------------------------------
try:
    from embit import bip32, bip39, networks, script
    from embit.psbt import PSBT, InputScope, OutputScope, DerivationPath
    from embit.transaction import (
        Transaction, TransactionInput, TransactionOutput,
    )
except ImportError as exc:
    sys.stderr.write(
        "error: this script needs the 'embit' package.\n"
        "install with:  pip install embit\n"
        f"underlying error: {exc}\n"
    )
    sys.exit(1)

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
TEST_MNEMONIC = (
    "call release rib regret puzzle magic economy tragic various embody give road"
)
EXPECTED_FP_HEX = "9581fdb1"

NET = networks.NETWORKS["test"]            # testnet (coin type 1)

DEFAULT_AMOUNT = 100_000                   # sats per synthetic UTXO
DUST_AMOUNT = 546                          # P2WPKH/P2TR dust floor
DEFAULT_FEE = 1_000                        # sats; trivial flat fee

DEFAULT_SEQUENCE = 0xFFFFFFFD              # RBF-signaling
FINAL_SEQUENCE = 0xFFFFFFFF                # opt-out of RBF + locktime

SH_DEFAULT = 0x00                          # taproot "sign with default"
SH_ALL = 0x01
SH_NONE = 0x02
SH_SINGLE = 0x03
SH_ACP = 0x80                              # ANYONECANPAY flag

# Derivation roots (testnet, account 0)
PATH_P2WPKH = "m/84h/1h/0h"
PATH_P2TR = "m/86h/1h/0h"
PATH_P2SH_P2WPKH = "m/49h/1h/0h"
PATH_P2WSH = "m/48h/1h/0h/2h"

UNSIGNED_DIR = Path(__file__).parent / "unsigned"

# --------------------------------------------------------------------------
# Case table
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Case:
    """One row in the corpus."""

    name: str                                  # filename stem; no extension
    category: str                              # dispatch key
    sighash: int = SH_ALL                      # input sighash byte
    n_inputs: int = 1
    n_outputs: int = 2
    multisig: Optional[Tuple[int, int]] = None # (m, n) for *wsh cases
    locktime: int = 0
    sequence: int = DEFAULT_SEQUENCE
    amount: int = DEFAULT_AMOUNT
    notes: str = ""
    # If set, the corresponding builder is expected to fail under V1.0
    # FKT and the runner should mark it XFAIL.
    xfail: bool = False


# Reads top to bottom; do NOT renumber.  Append-only.
CASES: List[Case] = [
    # ---- p2wpkh (10) -----------------------------------------------------
    Case("p2wpkh_all_1in_2out",          "p2wpkh"),
    Case("p2wpkh_all_2in_2out",          "p2wpkh", n_inputs=2),
    Case("p2wpkh_all_3in_2out",          "p2wpkh", n_inputs=3),
    Case("p2wpkh_all_1in_1out",          "p2wpkh", n_outputs=1),
    Case("p2wpkh_all_1in_3out",          "p2wpkh", n_outputs=3),
    Case("p2wpkh_single_1in_2out",       "p2wpkh", sighash=SH_SINGLE),
    Case("p2wpkh_none_1in_2out",         "p2wpkh", sighash=SH_NONE,
         xfail=True, notes="V1.0 rejects SIGHASH_NONE"),
    Case("p2wpkh_all_acp_1in_2out",      "p2wpkh", sighash=SH_ALL | SH_ACP,
         xfail=True, notes="V1.0 rejects ANYONECANPAY"),
    Case("p2wpkh_dust_1in_2out",         "p2wpkh", amount=DUST_AMOUNT * 4),
    Case("p2wpkh_locktime_1in_2out",     "p2wpkh", locktime=800_000),

    # ---- p2tr keypath (12) ----------------------------------------------
    Case("p2tr_keypath_default_1in_2out","p2tr_keypath", sighash=SH_DEFAULT),
    Case("p2tr_keypath_all_1in_2out",    "p2tr_keypath", sighash=SH_ALL),
    Case("p2tr_keypath_default_2in_2out","p2tr_keypath", sighash=SH_DEFAULT,
         n_inputs=2),
    Case("p2tr_keypath_default_3in_2out","p2tr_keypath", sighash=SH_DEFAULT,
         n_inputs=3),
    Case("p2tr_keypath_default_1in_1out","p2tr_keypath", sighash=SH_DEFAULT,
         n_outputs=1),
    Case("p2tr_keypath_default_1in_3out","p2tr_keypath", sighash=SH_DEFAULT,
         n_outputs=3),
    Case("p2tr_keypath_single_1in_2out", "p2tr_keypath", sighash=SH_SINGLE),
    Case("p2tr_keypath_none_1in_2out",   "p2tr_keypath", sighash=SH_NONE,
         xfail=True, notes="V1.0 rejects SIGHASH_NONE"),
    Case("p2tr_keypath_all_acp_1in_2out","p2tr_keypath",
         sighash=SH_ALL | SH_ACP,
         xfail=True, notes="V1.0 rejects ANYONECANPAY"),
    Case("p2tr_keypath_dust_1in_2out",   "p2tr_keypath", sighash=SH_DEFAULT,
         amount=DUST_AMOUNT * 4),
    Case("p2tr_keypath_locktime_1in_2out","p2tr_keypath", sighash=SH_DEFAULT,
         locktime=800_000),
    Case("p2tr_keypath_to_p2wpkh_1in_1out","p2tr_keypath", sighash=SH_DEFAULT,
         n_outputs=1, notes="receiver is P2WPKH"),

    # ---- p2sh-p2wpkh (5) -------------------------------------------------
    Case("p2sh_p2wpkh_all_1in_2out",     "p2sh_p2wpkh", xfail=True,
         notes="V1.5 deferred"),
    Case("p2sh_p2wpkh_all_2in_2out",     "p2sh_p2wpkh", n_inputs=2,
         xfail=True, notes="V1.5 deferred"),
    Case("p2sh_p2wpkh_single_1in_2out",  "p2sh_p2wpkh", sighash=SH_SINGLE,
         xfail=True, notes="V1.5 deferred"),
    Case("p2sh_p2wpkh_all_acp_1in_2out", "p2sh_p2wpkh",
         sighash=SH_ALL | SH_ACP,
         xfail=True, notes="V1.5 deferred"),
    Case("p2sh_p2wpkh_locktime_1in_2out","p2sh_p2wpkh", locktime=800_000,
         xfail=True, notes="V1.5 deferred"),

    # ---- p2wsh multisig (8) ---------------------------------------------
    Case("p2wsh_1of1_all_1in_2out",      "p2wsh", multisig=(1, 1),
         xfail=True, notes="V1.5 deferred"),
    Case("p2wsh_2of2_all_1in_2out",      "p2wsh", multisig=(2, 2),
         xfail=True, notes="V1.5 deferred"),
    Case("p2wsh_2of3_all_1in_2out",      "p2wsh", multisig=(2, 3),
         xfail=True, notes="V1.5 deferred"),
    Case("p2wsh_3of5_all_1in_2out",      "p2wsh", multisig=(3, 5),
         xfail=True, notes="V1.5 deferred"),
    Case("p2wsh_2of3_all_2in_2out",      "p2wsh", multisig=(2, 3),
         n_inputs=2, xfail=True, notes="V1.5 deferred"),
    Case("p2wsh_2of3_single_1in_2out",   "p2wsh", multisig=(2, 3),
         sighash=SH_SINGLE, xfail=True, notes="V1.5 deferred"),
    Case("p2wsh_2of3_all_acp_1in_2out",  "p2wsh", multisig=(2, 3),
         sighash=SH_ALL | SH_ACP, xfail=True, notes="V1.5 deferred"),
    Case("p2wsh_2of3_all_3in_2out",      "p2wsh", multisig=(2, 3),
         n_inputs=3, xfail=True, notes="V1.5 deferred"),

    # ---- p2sh-p2wsh multisig (5) ----------------------------------------
    Case("p2sh_p2wsh_1of1_all_1in_2out", "p2sh_p2wsh", multisig=(1, 1),
         xfail=True, notes="V1.5 deferred"),
    Case("p2sh_p2wsh_2of2_all_1in_2out", "p2sh_p2wsh", multisig=(2, 2),
         xfail=True, notes="V1.5 deferred"),
    Case("p2sh_p2wsh_2of3_all_1in_2out", "p2sh_p2wsh", multisig=(2, 3),
         xfail=True, notes="V1.5 deferred"),
    Case("p2sh_p2wsh_2of3_all_2in_2out", "p2sh_p2wsh", multisig=(2, 3),
         n_inputs=2, xfail=True, notes="V1.5 deferred"),
    Case("p2sh_p2wsh_2of3_single_1in_2out","p2sh_p2wsh", multisig=(2, 3),
         sighash=SH_SINGLE, xfail=True, notes="V1.5 deferred"),

    # ---- mixed / edge (11) ----------------------------------------------
    Case("mixed_p2wpkh_p2tr_2in_2out",       "mixed_p2wpkh_p2tr",
         n_inputs=2, sighash=SH_ALL),
    Case("mixed_p2wpkh_p2sh_p2wpkh_2in_2out","mixed_p2wpkh_p2sh_p2wpkh",
         n_inputs=2, xfail=True, notes="needs V1.5 P2SH-P2WPKH"),
    Case("mixed_p2wsh_p2tr_2in_2out",        "mixed_p2wsh_p2tr",
         n_inputs=2, xfail=True, notes="needs V1.5 P2WSH"),
    Case("mixed_p2sh_p2wpkh_p2tr_2in_2out",  "mixed_p2sh_p2wpkh_p2tr",
         n_inputs=2, xfail=True, notes="needs V1.5 P2SH-P2WPKH"),
    Case("p2wpkh_nonwitness_only_1in_2out",  "p2wpkh",
         notes="non-witness UTXO only"),
    Case("p2wpkh_both_utxos_1in_2out",       "p2wpkh",
         notes="emits both witness and non-witness UTXO"),
    Case("p2wpkh_zero_fp_1in_2out",          "p2wpkh",
         notes="bip32 fingerprint zeroed out (wallet wildcard)"),
    Case("p2wpkh_high_locktime_1in_2out",    "p2wpkh", locktime=2_000_000_000),
    Case("p2wpkh_final_seq_1in_2out",        "p2wpkh", sequence=FINAL_SEQUENCE),
    Case("p2wpkh_consolidate_3in_1out",      "p2wpkh",
         n_inputs=3, n_outputs=1),
    Case("p2tr_keypath_consolidate_3in_1out","p2tr_keypath",
         sighash=SH_DEFAULT, n_inputs=3, n_outputs=1),
]


# --------------------------------------------------------------------------
# HD key plumbing
# --------------------------------------------------------------------------
def root_key() -> bip32.HDKey:
    """Master HDKey derived from the test mnemonic (testnet xprv)."""
    seed = bip39.mnemonic_to_seed(TEST_MNEMONIC)
    return bip32.HDKey.from_seed(seed, version=NET["xprv"])


def master_fp(root: bip32.HDKey) -> bytes:
    """Big-endian 4-byte master fingerprint (matches FKT master_fp)."""
    return root.my_fingerprint


# --------------------------------------------------------------------------
# Synthetic prev-tx helpers
# --------------------------------------------------------------------------
def _empty_script() -> "script.Script":
    return script.Script(b"")


def fake_prev_tx(amount: int, script_pubkey: bytes) -> Transaction:
    """One-input one-output coinbase-like tx funding ``script_pubkey``.

    The previous txid is deterministic because the input is a synthetic
    coinbase referencing the all-zero outpoint with a predictable
    nSequence. It will NEVER be a real on-chain tx, so this is safe.
    """
    funding_in = TransactionInput(
        b"\x00" * 32, 0xFFFFFFFF, _empty_script(), FINAL_SEQUENCE,
    )
    funding_out = TransactionOutput(amount, script.Script(script_pubkey))
    return Transaction(2, [funding_in], [funding_out], 0)


# --------------------------------------------------------------------------
# Per-key derivations
# --------------------------------------------------------------------------
def derive_p2wpkh(root: bip32.HDKey, idx: int) -> Tuple[bip32.HDKey, str, bytes]:
    """Return (priv, derivation, scriptPubKey) for input ``idx``."""
    deriv = f"{PATH_P2WPKH}/0/{idx}"
    child = root.derive(deriv)
    return child, deriv, script.p2wpkh(child).data


def derive_p2tr(root: bip32.HDKey, idx: int) -> Tuple[bip32.HDKey, str, bytes]:
    """Return (priv, derivation, tweaked scriptPubKey)."""
    deriv = f"{PATH_P2TR}/0/{idx}"
    child = root.derive(deriv)
    return child, deriv, script.p2tr(child).data


def derive_change_p2wpkh(root: bip32.HDKey, idx: int) -> bytes:
    return script.p2wpkh(root.derive(f"{PATH_P2WPKH}/1/{idx}")).data


def derive_change_p2tr(root: bip32.HDKey, idx: int) -> bytes:
    return script.p2tr(root.derive(f"{PATH_P2TR}/1/{idx}")).data


# --------------------------------------------------------------------------
# Output spread helpers
# --------------------------------------------------------------------------
def spread_outputs(total_in: int, n_outputs: int, change_spk: bytes,
                   external_spk: bytes) -> List[TransactionOutput]:
    """Distribute funds across ``n_outputs`` outputs, change last."""
    spendable = total_in - DEFAULT_FEE
    if n_outputs == 1:
        return [TransactionOutput(spendable, script.Script(external_spk))]
    per_external = spendable // n_outputs
    outs: List[TransactionOutput] = []
    for _ in range(n_outputs - 1):
        outs.append(TransactionOutput(
            per_external, script.Script(external_spk)))
    change_value = spendable - per_external * (n_outputs - 1)
    outs.append(TransactionOutput(change_value, script.Script(change_spk)))
    return outs


# --------------------------------------------------------------------------
# PSBT skeleton
# --------------------------------------------------------------------------
def fresh_psbt(case: Case) -> PSBT:
    p = PSBT()
    p.tx_version = 2
    p.locktime = case.locktime
    return p


def make_input(prev_tx: Transaction, vout_idx: int,
               case: Case) -> InputScope:
    """Common InputScope wrapper carrying the spending TransactionInput."""
    return InputScope(vin=TransactionInput(
        prev_tx.txid(), vout_idx, _empty_script(), case.sequence,
    ))


# --------------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------------
def build_p2wpkh(case: Case, root: bip32.HDKey) -> bytes:
    """All-P2WPKH PSBT honouring ``case``."""
    fp = master_fp(root)
    if case.name.endswith("zero_fp_1in_2out"):
        fp = b"\x00\x00\x00\x00"

    p = fresh_psbt(case)
    total_in = 0
    for i in range(case.n_inputs):
        child, deriv, spk = derive_p2wpkh(root, i)
        prev = fake_prev_tx(case.amount, spk)
        inp = make_input(prev, 0, case)
        if "nonwitness_only" in case.name:
            inp.non_witness_utxo = prev
        elif "both_utxos" in case.name:
            inp.witness_utxo = prev.vout[0]
            inp.non_witness_utxo = prev
        else:
            inp.witness_utxo = prev.vout[0]
        if case.sighash != 0:
            inp.sighash_type = case.sighash
        inp.bip32_derivations[child.key.get_public_key()] = DerivationPath(
            fp, bip32.parse_path(deriv))
        p.inputs.append(inp)
        total_in += case.amount

    _, _, ext_spk = derive_p2wpkh(root, 999)
    change_spk = derive_change_p2wpkh(root, 0)
    for vo in spread_outputs(total_in, case.n_outputs, change_spk, ext_spk):
        p.outputs.append(OutputScope(vout=vo))

    # Tag last output as change so reference signers know.
    last_change_child = root.derive(f"{PATH_P2WPKH}/1/0")
    p.outputs[-1].bip32_derivations[
        last_change_child.key.get_public_key()
    ] = DerivationPath(fp, bip32.parse_path(f"{PATH_P2WPKH}/1/0"))
    return p.serialize()


def build_p2tr_keypath(case: Case, root: bip32.HDKey) -> bytes:
    """All-Taproot key-path PSBT honouring ``case``."""
    fp = master_fp(root)
    p = fresh_psbt(case)
    total_in = 0
    for i in range(case.n_inputs):
        child, deriv, spk = derive_p2tr(root, i)
        prev = fake_prev_tx(case.amount, spk)
        inp = make_input(prev, 0, case)
        inp.witness_utxo = prev.vout[0]
        if case.sighash != SH_DEFAULT:
            inp.sighash_type = case.sighash
        pub = child.key.get_public_key()
        inp.taproot_internal_key = pub
        inp.taproot_bip32_derivations[pub] = (
            [],
            DerivationPath(fp, bip32.parse_path(deriv)),
        )
        p.inputs.append(inp)
        total_in += case.amount

    if case.name.endswith("to_p2wpkh_1in_1out"):
        _, _, ext_spk = derive_p2wpkh(root, 999)
    else:
        _, _, ext_spk = derive_p2tr(root, 999)
    change_spk = derive_change_p2tr(root, 0)
    for vo in spread_outputs(total_in, case.n_outputs, change_spk, ext_spk):
        p.outputs.append(OutputScope(vout=vo))
    return p.serialize()


def build_p2sh_p2wpkh(case: Case, root: bip32.HDKey) -> bytes:
    """BIP-49 P2SH-wrapped P2WPKH PSBT (deferred coverage)."""
    fp = master_fp(root)
    p = fresh_psbt(case)
    total_in = 0
    for i in range(case.n_inputs):
        deriv = f"{PATH_P2SH_P2WPKH}/0/{i}"
        child = root.derive(deriv)
        redeem = script.p2wpkh(child)                 # 0x00 0x14 <hash160>
        spk = script.p2sh(redeem).data                # 0xa9 0x14 <h> 0x87
        prev = fake_prev_tx(case.amount, spk)
        inp = make_input(prev, 0, case)
        inp.witness_utxo = prev.vout[0]
        inp.redeem_script = redeem
        if case.sighash != 0:
            inp.sighash_type = case.sighash
        inp.bip32_derivations[child.key.get_public_key()] = DerivationPath(
            fp, bip32.parse_path(deriv))
        p.inputs.append(inp)
        total_in += case.amount

    _, _, ext_spk = derive_p2wpkh(root, 999)
    change_spk = derive_change_p2wpkh(root, 0)
    for vo in spread_outputs(total_in, case.n_outputs, change_spk, ext_spk):
        p.outputs.append(OutputScope(vout=vo))
    return p.serialize()


def _multisig_witness_script(root: bip32.HDKey, m: int, n: int,
                             group_idx: int) -> Tuple[script.Script,
                                                       List[bip32.HDKey],
                                                       List[str]]:
    """OP_M <pub1> <pub2> ... <pubN> OP_N OP_CHECKMULTISIG (BIP-67 sorted)."""
    keys: List[bip32.HDKey] = []
    derivs: List[str] = []
    for i in range(n):
        deriv = f"{PATH_P2WSH}/0/{group_idx * 16 + i}"
        keys.append(root.derive(deriv))
        derivs.append(deriv)
    pubkeys = sorted(k.key.get_public_key().sec() for k in keys)
    body = bytearray()
    body.append(0x50 + m)          # OP_m
    for pk in pubkeys:
        body.append(len(pk))
        body.extend(pk)
    body.append(0x50 + n)          # OP_n
    body.append(0xAE)              # OP_CHECKMULTISIG
    return script.Script(bytes(body)), keys, derivs


def build_p2wsh(case: Case, root: bip32.HDKey) -> bytes:
    """Native P2WSH multisig PSBT (deferred coverage)."""
    if case.multisig is None:
        raise ValueError(f"{case.name}: p2wsh case must declare multisig=(m,n)")
    m, n = case.multisig
    fp = master_fp(root)
    p = fresh_psbt(case)
    total_in = 0
    for i in range(case.n_inputs):
        ws, keys, derivs = _multisig_witness_script(root, m, n, i)
        spk = script.p2wsh(ws).data
        prev = fake_prev_tx(case.amount, spk)
        inp = make_input(prev, 0, case)
        inp.witness_utxo = prev.vout[0]
        inp.witness_script = ws
        if case.sighash != 0:
            inp.sighash_type = case.sighash
        for k, d in zip(keys, derivs):
            inp.bip32_derivations[k.key.get_public_key()] = DerivationPath(
                fp, bip32.parse_path(d))
        p.inputs.append(inp)
        total_in += case.amount

    _, _, ext_spk = derive_p2wpkh(root, 999)
    change_spk = derive_change_p2wpkh(root, 0)
    for vo in spread_outputs(total_in, case.n_outputs, change_spk, ext_spk):
        p.outputs.append(OutputScope(vout=vo))
    return p.serialize()


def build_p2sh_p2wsh(case: Case, root: bip32.HDKey) -> bytes:
    """P2SH-wrapped P2WSH multisig PSBT (deferred coverage)."""
    if case.multisig is None:
        raise ValueError(f"{case.name}: p2sh_p2wsh case must declare multisig")
    m, n = case.multisig
    fp = master_fp(root)
    p = fresh_psbt(case)
    total_in = 0
    for i in range(case.n_inputs):
        ws, keys, derivs = _multisig_witness_script(root, m, n, i)
        redeem = script.p2wsh(ws)                     # 0x00 0x20 <sha256(ws)>
        spk = script.p2sh(redeem).data
        prev = fake_prev_tx(case.amount, spk)
        inp = make_input(prev, 0, case)
        inp.witness_utxo = prev.vout[0]
        inp.redeem_script = redeem
        inp.witness_script = ws
        if case.sighash != 0:
            inp.sighash_type = case.sighash
        for k, d in zip(keys, derivs):
            inp.bip32_derivations[k.key.get_public_key()] = DerivationPath(
                fp, bip32.parse_path(d))
        p.inputs.append(inp)
        total_in += case.amount

    _, _, ext_spk = derive_p2wpkh(root, 999)
    change_spk = derive_change_p2wpkh(root, 0)
    for vo in spread_outputs(total_in, case.n_outputs, change_spk, ext_spk):
        p.outputs.append(OutputScope(vout=vo))
    return p.serialize()


# --------------------------------------------------------------------------
# Mixed-input builders
# --------------------------------------------------------------------------
def _add_p2wpkh_input(p: PSBT, root: bip32.HDKey, idx: int,
                     case: Case, fp: bytes) -> int:
    child, deriv, spk = derive_p2wpkh(root, 100 + idx)
    prev = fake_prev_tx(case.amount, spk)
    inp = make_input(prev, 0, case)
    inp.witness_utxo = prev.vout[0]
    if case.sighash != 0:
        inp.sighash_type = case.sighash
    inp.bip32_derivations[child.key.get_public_key()] = DerivationPath(
        fp, bip32.parse_path(deriv))
    p.inputs.append(inp)
    return case.amount


def _add_p2tr_input(p: PSBT, root: bip32.HDKey, idx: int,
                   case: Case, fp: bytes) -> int:
    child, deriv, spk = derive_p2tr(root, 100 + idx)
    prev = fake_prev_tx(case.amount, spk)
    inp = make_input(prev, 0, case)
    inp.witness_utxo = prev.vout[0]
    if case.sighash != SH_DEFAULT and case.sighash != 0:
        inp.sighash_type = case.sighash
    pub = child.key.get_public_key()
    inp.taproot_internal_key = pub
    inp.taproot_bip32_derivations[pub] = (
        [], DerivationPath(fp, bip32.parse_path(deriv)))
    p.inputs.append(inp)
    return case.amount


def _add_p2sh_p2wpkh_input(p: PSBT, root: bip32.HDKey, idx: int,
                          case: Case, fp: bytes) -> int:
    deriv = f"{PATH_P2SH_P2WPKH}/0/{100 + idx}"
    child = root.derive(deriv)
    redeem = script.p2wpkh(child)
    spk = script.p2sh(redeem).data
    prev = fake_prev_tx(case.amount, spk)
    inp = make_input(prev, 0, case)
    inp.witness_utxo = prev.vout[0]
    inp.redeem_script = redeem
    if case.sighash != 0:
        inp.sighash_type = case.sighash
    inp.bip32_derivations[child.key.get_public_key()] = DerivationPath(
        fp, bip32.parse_path(deriv))
    p.inputs.append(inp)
    return case.amount


def _add_p2wsh_input(p: PSBT, root: bip32.HDKey, idx: int,
                    case: Case, fp: bytes) -> int:
    ws, keys, derivs = _multisig_witness_script(root, 2, 3, 200 + idx)
    spk = script.p2wsh(ws).data
    prev = fake_prev_tx(case.amount, spk)
    inp = make_input(prev, 0, case)
    inp.witness_utxo = prev.vout[0]
    inp.witness_script = ws
    if case.sighash != 0:
        inp.sighash_type = case.sighash
    for k, d in zip(keys, derivs):
        inp.bip32_derivations[k.key.get_public_key()] = DerivationPath(
            fp, bip32.parse_path(d))
    p.inputs.append(inp)
    return case.amount


def _build_mix(case: Case, root: bip32.HDKey,
              kinds: Tuple[str, str]) -> bytes:
    """Build a 2-input PSBT where inputs come from two categories."""
    fp = master_fp(root)
    p = fresh_psbt(case)
    total_in = 0
    adders = {
        "p2wpkh": _add_p2wpkh_input,
        "p2tr": _add_p2tr_input,
        "p2sh_p2wpkh": _add_p2sh_p2wpkh_input,
        "p2wsh": _add_p2wsh_input,
    }
    for i, kind in enumerate(kinds):
        if kind not in adders:
            raise ValueError(f"unknown mix kind: {kind}")
        total_in += adders[kind](p, root, i, case, fp)

    _, _, ext_spk = derive_p2wpkh(root, 999)
    change_spk = derive_change_p2wpkh(root, 0)
    for vo in spread_outputs(total_in, case.n_outputs, change_spk, ext_spk):
        p.outputs.append(OutputScope(vout=vo))
    return p.serialize()


def build_mixed_p2wpkh_p2tr(case: Case, root: bip32.HDKey) -> bytes:
    return _build_mix(case, root, ("p2wpkh", "p2tr"))


def build_mixed_p2wpkh_p2sh_p2wpkh(case: Case, root: bip32.HDKey) -> bytes:
    return _build_mix(case, root, ("p2wpkh", "p2sh_p2wpkh"))


def build_mixed_p2wsh_p2tr(case: Case, root: bip32.HDKey) -> bytes:
    return _build_mix(case, root, ("p2wsh", "p2tr"))


def build_mixed_p2sh_p2wpkh_p2tr(case: Case, root: bip32.HDKey) -> bytes:
    return _build_mix(case, root, ("p2sh_p2wpkh", "p2tr"))


# --------------------------------------------------------------------------
# Dispatcher
# --------------------------------------------------------------------------
BUILDERS: dict = {
    "p2wpkh": build_p2wpkh,
    "p2tr_keypath": build_p2tr_keypath,
    "p2sh_p2wpkh": build_p2sh_p2wpkh,
    "p2wsh": build_p2wsh,
    "p2sh_p2wsh": build_p2sh_p2wsh,
    "mixed_p2wpkh_p2tr": build_mixed_p2wpkh_p2tr,
    "mixed_p2wpkh_p2sh_p2wpkh": build_mixed_p2wpkh_p2sh_p2wpkh,
    "mixed_p2wsh_p2tr": build_mixed_p2wsh_p2tr,
    "mixed_p2sh_p2wpkh_p2tr": build_mixed_p2sh_p2wpkh_p2tr,
}


def build(case: Case, root: bip32.HDKey) -> bytes:
    builder = BUILDERS.get(case.category)
    if builder is None:
        raise NotImplementedError(
            f"no builder registered for category '{case.category}' "
            f"(case '{case.name}')")
    return builder(case, root)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    UNSIGNED_DIR.mkdir(parents=True, exist_ok=True)

    root = root_key()
    fp_hex = master_fp(root).hex()
    if fp_hex != EXPECTED_FP_HEX:
        sys.stderr.write(
            f"warning: master fingerprint mismatch: got {fp_hex}, "
            f"expected {EXPECTED_FP_HEX}. The seed or embit version may "
            f"have changed.\n")

    if len(CASES) != 51:
        sys.stderr.write(
            f"warning: expected 51 cases, found {len(CASES)}. The corpus "
            f"label is now wrong.\n")

    n_ok = 0
    n_skip = 0
    n_err = 0
    for case in CASES:
        out_path = UNSIGNED_DIR / f"{case.name}.psbt"
        try:
            blob = build(case, root)
        except NotImplementedError as exc:
            sys.stderr.write(f"SKIP  {case.name}: {exc}\n")
            n_skip += 1
            continue
        except Exception as exc:                       # pragma: no cover
            sys.stderr.write(f"ERR   {case.name}: {exc!r}\n")
            n_err += 1
            continue
        out_path.write_bytes(blob)
        marker = "xfail" if case.xfail else "ok"
        print(f"{marker:>5}  {case.name:<42}  {len(blob):>4} bytes")
        n_ok += 1

    print(f"\nwrote {n_ok}/{len(CASES)} PSBTs to {UNSIGNED_DIR}")
    if n_skip:
        print(f"skipped {n_skip} (no builder yet)")
    if n_err:
        print(f"errors {n_err}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
