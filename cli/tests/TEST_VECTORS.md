# FKT Test Vectors Checklist

**Goal**: Build ~100–110 real test vectors across V1–V4.  
For each vector, save **both** an unsigned and a signed version.

**Status Legend**:
- [ ] = Not started
- [x] = Unsigned PSBT created
- [x] = Sparrow-signed (reference)
- [x] = FKT-signed successfully
- [x] = Verified (matches Sparrow / works on-chain for Ark)

---

## V1 – Core Single-Sig (~20 vectors)

| ID    | Filename                              | Script Type   | Key Variations                     | How to Build in Sparrow                              | Status |
|-------|---------------------------------------|---------------|------------------------------------|------------------------------------------------------|--------|
| V1-01 | v1_p2wpkh_1in_1out                    | P2WPKH        | Baseline                           | Normal send in BIP84 wallet                          | [ ]    |
| V1-02 | v1_p2wpkh_2in_2out                    | P2WPKH        | Multi-input + change               | Select 2 UTXOs in Inputs tab                         | [ ]    |
| V1-03 | v1_p2wpkh_3in_1out                    | P2WPKH        | Consolidation                      | Select 3 UTXOs                                       | [ ]    |
| V1-04 | v1_p2wpkh_rbf                         | P2WPKH        | RBF enabled                        | Enable RBF checkbox                                  | [ ]    |
| V1-05 | v1_p2wpkh_locktime                    | P2WPKH        | Non-zero locktime                  | Advanced → Set Locktime                              | [ ]    |
| V1-06 | v1_p2wpkh_dust                        | P2WPKH        | Dust output                        | Send very small amount (~546 sats)                   | [ ]    |
| V1-07 | v1_p2wpkh_high_locktime               | P2WPKH        | Very high locktime                 | Advanced → Set high Locktime                         | [ ]    |
| V1-08 | v1_p2tr_1in_1out                      | P2TR          | Simple Taproot                     | Normal send in BIP86 wallet                          | [ ]    |
| V1-09 | v1_p2tr_2in_2out                      | P2TR          | Multi-input Taproot                | Select 2 UTXOs in BIP86 wallet                       | [ ]    |
| V1-10 | v1_p2tr_rbf                           | P2TR          | RBF + Taproot                      | BIP86 + Enable RBF                                   | [ ]    |
| V1-11 | v1_p2tr_locktime                      | P2TR          | Locktime + Taproot                 | BIP86 + Set Locktime                                 | [ ]    |
| V1-12 | v1_p2tr_dust                          | P2TR          | Dust output (Taproot)              | Send very small amount from BIP86                    | [ ]    |
| V1-13 | v1_p2sh_p2wpkh_1in_1out               | P2SH-P2WPKH   | Wrapped SegWit                     | Normal send in BIP49 wallet                          | [ ]    |
| V1-14 | v1_p2sh_p2wpkh_rbf                    | P2SH-P2WPKH   | RBF + Wrapped                      | BIP49 + Enable RBF                                   | [ ]    |
| V1-15 | v1_p2sh_p2wpkh_locktime               | P2SH-P2WPKH   | Locktime + Wrapped                 | BIP49 + Set Locktime                                 | [ ]    |
| V1-16 | v1_mixed_p2wpkh_p2tr_2in_2out         | Mixed         | P2WPKH + P2TR inputs               | Start in BIP84, add UTXO from BIP86 wallet           | [ ]    |
| V1-17 | v1_p2wpkh_consolidate_3in_1out        | P2WPKH        | 3-input consolidation              | Select 3 UTXOs, send to 1 output                     | [ ]    |
| V1-18 | v1_p2wpkh_minimal_fee                 | P2WPKH        | Very low fee                       | Set very low fee rate                                | [ ]    |
| V1-19 | v1_p2tr_minimal_fee                   | P2TR          | Very low fee (Taproot)             | BIP86 + very low fee rate                            | [ ]    |
| V1-20 | v1_reject_duplicate_outpoint          | P2WPKH        | Duplicate outpoint (reject)        | Manually create invalid PSBT or use synthetic        | [ ]    |

---

## V2 – Practical Multisig (~22 vectors)

| ID    | Filename                              | Script Type   | Key Variations                     | How to Build in Sparrow                                      | Status |
|-------|---------------------------------------|---------------|------------------------------------|--------------------------------------------------------------|--------|
| V2-01 | v2_p2wsh_2of2_1in_1out                | P2WSH         | 2-of-2 multisig                    | Create 2-of-2 multisig wallet → Normal send                  | [ ]    |
| V2-02 | v2_p2wsh_2of2_2in_2out                | P2WSH         | 2-of-2 + multi-input               | Multisig wallet + select 2 UTXOs                             | [ ]    |
| V2-03 | v2_p2wsh_2of3_1in_1out                | P2WSH         | 2-of-3 multisig                    | Create 2-of-3 multisig wallet                                | [ ]    |
| V2-04 | v2_p2wsh_2of3_2in_2out                | P2WSH         | 2-of-3 + multi-input               | 2-of-3 multisig + select 2 UTXOs                             | [ ]    |
| V2-05 | v2_p2sh_p2wsh_2of2_1in_1out           | P2SH-P2WSH    | Wrapped 2-of-2                     | Create wrapped multisig (or use Nested option)               | [ ]    |
| V2-06 | v2_p2sh_p2wsh_2of3_1in_1out           | P2SH-P2WSH    | Wrapped 2-of-3                     | Wrapped 2-of-3 multisig                                      | [ ]    |
| V2-07 | v2_mixed_p2wpkh_p2wsh_2in_2out        | Mixed         | P2WPKH + P2WSH                     | Start in P2WPKH wallet, add UTXO from multisig wallet        | [ ]    |
| V2-08 | v2_p2wsh_2of2_rbf                     | P2WSH         | 2-of-2 + RBF                       | Multisig + Enable RBF                                        | [ ]    |
| V2-09 | v2_p2wsh_2of3_locktime                | P2WSH         | 2-of-3 + Locktime                  | Multisig + Set Locktime                                      | [ ]    |
| V2-10 | v2_p2wsh_2of2_dust                    | P2WSH         | 2-of-2 + Dust                      | Send very small amount from multisig                         | [ ]    |

*(Add more V2 cases as needed — aim for ~20–24 total)*

---

## V3 – Stretch + Ark (~25 vectors)

**Note**: V3 requires stable Taproot script-path signing first.

### Mixed + Taproot Script-Path (Sparrow)

| ID    | Filename                              | Script Type          | Key Variations                     | How to Build in Sparrow                                      | Status |
|-------|---------------------------------------|----------------------|------------------------------------|--------------------------------------------------------------|--------|
| V3-01 | v3_mixed_p2wpkh_p2tr_2in_2out         | Mixed                | P2WPKH + P2TR                      | Start in BIP84, add UTXO from BIP86                          | [ ]    |
| V3-02 | v3_mixed_p2wpkh_p2wsh_2in_2out        | Mixed                | P2WPKH + P2WSH                     | Start in P2WPKH, add UTXO from multisig                      | [ ]    |
| V3-03 | v3_p2tr_script_path_simple            | P2TR Script-path     | Basic single-leaf Tapscript        | Use Sparrow script editor → create simple script → spend     | [ ]    |

### Ark Vectors (Generated via `bark` CLI on Signet)

| ID    | Filename                        | Type          | Key Variations                  | How to Build                                      | Status |
|-------|---------------------------------|---------------|---------------------------------|---------------------------------------------------|--------|
| V3-04 | v3_ark_boarding_basic           | Ark Boarding  | Basic boarding                  | `bark --network signet onboard ...`               | [ ]    |
| V3-05 | v3_ark_exit_simple              | Ark Exit      | Simple unilateral exit          | `bark --network signet exit ...`                  | [ ]    |
| V3-06 | v3_ark_exit_with_change         | Ark Exit      | Exit with change output         | `bark exit` with change                           | [ ]    |
| V3-07 | v3_ark_exit_malformed           | Ark Exit      | Malformed (graceful reject)     | Manually corrupt or use invalid case              | [ ]    |

*(Expand Ark cases as Bark CLI capabilities grow)*

---

## V4 – Polish & Robustness (~25–30 vectors)

This version focuses on edge cases, stress tests, and graceful rejection.  
Many of these can be synthetic at first, then validated with real vectors.

**Examples of V4 vectors**:
- Very high input counts
- Unusual locktime + RBF combinations
- PSBTs with many proprietary keys
- Edge case fee situations
- Complex mixed input combinations
- Graceful rejection of various malformed PSBTs

---

## Summary

| Version | Target Count | Tool              | Priority | Notes |
|---------|--------------|-------------------|----------|-------|
| V1      | ~20          | Sparrow           | High     | Start here |
| V2      | ~22          | Sparrow           | High     | Multisig focus |
| V3      | ~25          | Sparrow + `bark`  | High     | Includes Ark |
| V4      | ~25–30       | Mixed             | Medium   | Polish + rejection |

**Plan**:
1. Create **unsigned** PSBT → save in `unsigned/`
2. Sign with **Sparrow** → save in `sparrow-signed/`
3. Sign with **FKT** → compare results
4. For Ark: Generate with `bark` on Signet → sign with FKT → verify exit works

---

**Would you like me to also create a shorter "Priority 1" checklist** (first 25 vectors) that you can knock out this week? That might be more manageable to start with. 