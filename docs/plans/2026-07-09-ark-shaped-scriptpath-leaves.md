# Spec: Ark-shaped script-path leaf templates (shapes only)

**Date:** 2026-07-09  
**Product:** FKT offline signer v0.2.x  
**Scope:** Synthetic fixtures that **resemble** bark user-exit leaves. Not full bark consensus, not MuSig, not live ASP.

---

## 1. Purpose

Prove FKT can script-path-sign tapscripts of the form used in unilateral exits:

```
witness: [ schnorr_sig, tapscript, control_block ]
```

with optional **CSV** (relative) and/or **CLTV** (absolute) prefixes before the user `OP_CHECKSIG`.

---

## 2. Leaf templates (byte shapes)

All leaves use leaf version `0xc0` (BIP342 Tapscript).  
`P` = 32-byte x-only pubkey of the user (BIP86 path `m/86'/1'/0'/0/0` in fixtures).

| ID | Name (bark-inspired) | Script (asm) | Notes |
|----|----------------------|--------------|--------|
| `checksig` | plain user leaf | `<P> OP_CHECKSIG` | Existing v0.2 synthetic |
| `csv` | DelayedSign-like | `<n> OP_CSV OP_DROP <P> OP_CHECKSIG` | Relative delay; fixture sets `nSequence` |
| `cltv` | TimelockSign-like | `<h> OP_CLTV OP_DROP <P> OP_CHECKSIG` | Absolute height; fixture sets `nLockTime` |
| `csv_cltv` | DelayedTimelockSign-like | `<n> OP_CSV OP_DROP <h> OP_CLTV OP_DROP <P> OP_CHECKSIG` | Both locks |

Opcodes (hex):

| Op | Hex |
|----|-----|
| OP_DROP | `75` |
| OP_CHECKSIG | `ac` |
| OP_CHECKLOCKTIMEVERIFY | `b1` |
| OP_CHECKSEQUENCEVERIFY | `b2` |
| push 32-byte key | `20` \|\| 32 bytes |

Fixture constants (testnet-oriented synthetic only):

| Symbol | Value | Encoding in script |
|--------|-------|--------------------|
| `n` (CSV) | 10 blocks | `01 0a` |
| `h` (CLTV) | 100 | `01 64` |

---

## 3. Transaction fields paired with leaves

FKT **does not** validate CSV/CLTV against a chain; it only signs the PSBT as given. Fixtures still set coherent fields so sighash matches a spend that *could* be valid:

| Leaf | `nSequence` | `nLockTime` |
|------|-------------|-------------|
| checksig | `0xfffffffd` (RBF) | 0 |
| csv | `10` (relative) | 0 |
| cltv | `0xfffffffe` (not max) | 100 |
| csv_cltv | `10` | 100 |

---

## 4. Tree / PSBT layout (all kinds)

Single-leaf tree (same as v0.2):

- Internal key = user x-only `P`  
- Merkle root = `TapLeaf(0xc0 \|\| compact_size(script) \|\| script)`  
- Control block = `(0xc0 \| parity) \|\| P`  
- PSBT: WITNESS_UTXO, TAP_INTERNAL_KEY, TAP_MERKLE_ROOT, TAP_LEAF_SCRIPT, TAP_BIP32_DERIVATION  

---

## 5. What FKT must do

1. Parse leaf + control block  
2. BIP341 **script-path** sighash (includes nSequence / nLockTime from unsigned tx)  
3. Untweaked Schnorr with user key  
4. Finalize witness `[sig, script, control_block]`  

No execution of CSV/CLTV in the signer.

---

## 6. Explicit non-goals

- Exact bark leaf byte-identity with production bark  
- Multi-leaf trees / internal key ≠ user  
- Server/cosign leaves  
- Live faucet  

---

## 7. Build / test

```bash
cd cli
make test-scriptpath          # plain checksig
make test-scriptpath-ark      # csv + cltv + csv_cltv + reject tree-without-leaf
```
