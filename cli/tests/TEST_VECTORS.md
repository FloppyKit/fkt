# FKT Test Vectors Checklist

**Goal**: Build ~100–110 real test vectors across V1–V4.  
For each vector, prefer **unsigned** + **Sparrow-signed** + **FKT-signed** goldens.

**Source of truth (Sparrow real):** `cli/tests/sparrow-real/manifest.json`  
**Seeds (TESTNET ONLY):** `cli/tests/TEST_SEEDS.md`  
**Harness:** `cd cli && make test-sparrow-real` / `make test-sparrow-real-golden`

**Status cells** (four flags, left→right):

| Flag | Meaning |
|------|---------|
| U | Unsigned PSBT present |
| S | Sparrow-signed reference present |
| F | FKT-signed golden committed under `fkt-signed/` |
| V | Verified by harness (sign + ECDSA/byte-match/structure) |

`[x]` = yes, `[ ]` = no / not yet.

Last updated: 2026-07-09 (test-matrix step 3)

---

## V1 – Core Single-Sig (Sparrow real matrix)

Canonical IDs match `sparrow-real/manifest.json` (not always `v1_` prefix).

### High priority

| ID | Manifest id | Script | U | S | F | V | Notes |
|----|-------------|--------|---|---|---|---|-------|
| V1-H01 | `p2wpkh_1in_1out` | P2WPKH | [x] | [x] | [x] | [x] | legacy seed hex |
| V1-H02 | `p2wpkh_2in_2out` | P2WPKH | [x] | [x] | [x] | [x] | multi-in + change |
| V1-H03 | `p2wpkh_rbf` | P2WPKH | [x] | [x] | [x] | [x] | |
| V1-H04 | `p2wpkh_locktime` | P2WPKH | [x] | [x] | [x] | [x] | |
| V1-H05 | `p2wpkh_with_change` | P2WPKH | [x] | [x] | [x] | [x] | alias of 2in_2out content |
| V1-H06 | `p2tr_1in_1out` | P2TR | [x] | [x] | [x] | [x] | byte-equal Sparrow; `call release` |
| V1-H07 | `p2tr_2in_2out` | P2TR | [x] | [x] | [x] | [x] | |
| V1-H08 | `p2tr_rbf` | P2TR | [x] | [x] | [x] | [x] | |
| V1-H09 | `mixed_p2wpkh_p2tr_2in_2out` | Mixed | [x] | [ ] | [x] | [x] | **TRUE** mixed: P2WPKH+P2TR inputs (merged from Sparrow legs; no single Sparrow-signed) |
| V1-H10 | `p2tr_script_path_synthetic` | P2TR script-path | [x] | [ ] | [ ] | [x] | v0.2 synthetic leaf; `make test-scriptpath` |

### Medium / low (default harness)

| ID | Manifest id | Script | U | S | F | V | Notes |
|----|-------------|--------|---|---|---|---|-------|
| V1-M01 | `p2wpkh_3in_1out` | P2WPKH | [x] | [x] | [x] | [x] | consolidation |
| V1-M02 | `p2wpkh_high_locktime` | P2WPKH | [x] | [x] | [x] | [x] | |
| V1-M03 | `p2tr_with_change` | P2TR | [x] | [x] | [x] | [x] | alias of p2tr_2in_2out |
| V1-M04 | `p2sh_p2wpkh_1in_1out` | P2SH-P2WPKH | [x] | [x] | [x] | [x] | nested; partial_sig insert; `reward parade…` |
| V1-M05 | `p2wsh_2of3_clean` | P2WSH | [x] | [ ] | [ ] | [ ] | SKIP — seed unknown / partial_sig product |
| V1-L01 | `p2tr_script_path` | P2TR keypath* | [x] | [x] | [x] | [x] | *named scriptpath; no 0x18/0x15; keypath sign |

### Bonus present (not in default golden set)

| Manifest id | U | S | F | V | Notes |
|-------------|---|---|---|---|-------|
| `p2wpkh_dust` | [x] | [x] | [ ] | [ ] | passes harness; not committed golden |
| `p2tr_dust` / `locktime` / `minimal_fee` | [x] | [x] | [ ] | [ ] | |
| mixed / nested / scriptpath **variants** (rbf-off, locktime, anyonecanpay) | [x] | partial | [ ] | [ ] | anyonecanpay may reject (sighash policy) |
| `multi_input_signs_index1` | [x] | [ ] | [ ] | [ ] | fails: pubkey mismatch input 0 |
| `nonwitness_utxo_mixed` | [x] | [ ] | [ ] | [ ] | fails: no inputs signed |
| `partial_sig` | [x] | [ ] | [ ] | [ ] | fails: already finalized |

### Checklist completeness (High)

All **9 High** cases: **U+S+F+V** complete as of step 3.

---

## V2 – Practical Multisig (~22 vectors)

| ID    | Filename                              | Script Type   | U | S | F | V | Notes |
|-------|---------------------------------------|---------------|---|---|---|---|-------|
| V2-01 | v2_p2wsh_2of2_1in_1out                | P2WSH         | [ ] | [ ] | [ ] | [ ] | |
| V2-02 | v2_p2wsh_2of2_2in_2out                | P2WSH         | [ ] | [ ] | [ ] | [ ] | |
| V2-03 | v2_p2wsh_2of3_1in_1out                | P2WSH         | [ ] | [ ] | [ ] | [ ] | have `p2wsh_2of3_clean` unsigned only |
| V2-04 | v2_p2wsh_2of3_2in_2out                | P2WSH         | [ ] | [ ] | [ ] | [ ] | |
| V2-05 | v2_p2sh_p2wsh_2of2_1in_1out           | P2SH-P2WSH    | [ ] | [ ] | [ ] | [ ] | |
| V2-06 | v2_p2sh_p2wsh_2of3_1in_1out           | P2SH-P2WSH    | [ ] | [ ] | [ ] | [ ] | |
| V2-07 | v2_mixed_p2wpkh_p2wsh_2in_2out        | Mixed         | [ ] | [ ] | [ ] | [ ] | |
| V2-08 | v2_p2wsh_2of2_rbf                     | P2WSH         | [ ] | [ ] | [ ] | [ ] | |
| V2-09 | v2_p2wsh_2of3_locktime                | P2WSH         | [ ] | [ ] | [ ] | [ ] | |
| V2-10 | v2_p2wsh_2of2_dust                    | P2WSH         | [ ] | [ ] | [ ] | [ ] | |

Policy: **partial_sig only** for P2WSH in v0.1 (not full finalize).

---

## V3 – Stretch + Ark (~25 vectors)

**Gate:** true Taproot script-path (0x18 / 0x15) + version bump when support lands.

| ID    | Filename                              | Script Type          | U | S | F | V | Notes |
|-------|---------------------------------------|----------------------|---|---|---|---|-------|
| V3-01 | true mixed p2wpkh+p2tr                | Mixed                | [x] | [ ] | [x] | [x] | Promoted to V1-H09; legs in `mixed-leg-p2wpkh` / `mixed-leg-p2tr` |
| V1-H10 | `p2tr_script_path_synthetic` | P2TR script-path | [x] | [ ] | [ ] | [x] | v0.2 synthetic leaf; `make test-scriptpath` |
| V3-02 | v3_mixed_p2wpkh_p2wsh_2in_2out        | Mixed                | [ ] | [ ] | [ ] | [ ] | |
| V3-03 | v3_p2tr_script_path_simple            | P2TR Script-path     | [ ] | [ ] | [ ] | [ ] | need leaf+control block fixtures |
| V3-04 | v3_ark_boarding_basic                 | Ark Boarding         | [ ] | [ ] | [ ] | [ ] | |
| V3-05 | v3_ark_exit_simple                    | Ark Exit             | [ ] | [ ] | [ ] | [ ] | offline claim after 0.2 |
| V3-06 | v3_ark_exit_with_change               | Ark Exit             | [ ] | [ ] | [ ] | [ ] | |
| V3-07 | v3_ark_exit_malformed                 | Ark Exit             | [ ] | [ ] | [ ] | [ ] | graceful reject |

---

## V4 – Polish & Robustness (~25–30 vectors)

Edge cases, stress, graceful rejection. Synthetic first, then real.

Examples: high input counts, proprietary keys, malformed PSBTs, fee edges.

---

## Regenerating goldens

```bash
cd cli
make test-sparrow-real              # sign + verify
make test-sparrow-real-golden       # also require byte-stable fkt-signed/
git status tests/sparrow-real/fkt-signed/
# If intentional crypto change: re-commit updated goldens with explanation.
```
