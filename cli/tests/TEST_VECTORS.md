# FKT Test Vectors Checklist

**Goal**: Build ~100–110 real test vectors across V1–V4.  
For each vector, prefer **unsigned** + **Sparrow-signed** + **FKT-signed** goldens.

**Source of truth (Sparrow real):** `cli/tests/sparrow-real/manifest.json`  
**Seeds (TESTNET ONLY):** `cli/tests/TEST_SEEDS.md`  
**Harness:** `cd cli && make test-sparrow-real` / `make test-sparrow-real-golden`  
**Full suite (Phase 1 Step 4):** `cd cli && make test`  
  BIP vectors · CLI entry · PSBT core · proprietary 0xFC · script-path ·  
  sparrow-real · multi-input · parity · Silent Payments stub

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

## V2 – Practical Multisig (native P2WSH cosign)

**Code bar (v0.3.0):** cosign + finalize when threshold met.  
**Auto:** `make test-multisig` (synthetic 1of1 / 2of2 / 2of3).  
**Manual Sparrow:** `docs/plans/2026-07-10-v2-multisig-sparrow-manual.md`

| ID    | Filename / case                       | Script Type   | U | S | F | V | Notes |
|-------|---------------------------------------|---------------|---|---|---|---|-------|
| V2-S1 | synthetic 1-of-1                      | P2WSH         | [x] | — | gen | [x] | `make test-multisig` finalize |
| V2-S2 | synthetic 2-of-2 A→B                  | P2WSH         | [x] | — | gen | [x] | partial then finalize |
| V2-S3 | synthetic 2-of-3 A→B                  | P2WSH         | [x] | — | gen | [x] | C unused |
| V2-S4 | synthetic wrong seed                  | P2WSH         | [x] | — | — | [x] | reject |
| V2-01 | p2wsh_1of1_sparrow                    | P2WSH         | [ ] | [ ] | [ ] | [ ] | **you** — Sparrow S1 |
| V2-02 | p2wsh_2of2_unsigned                   | P2WSH         | [ ] | [ ] | [ ] | [ ] | **you** — Sparrow S2 |
| V2-03 | p2wsh_2of2_partial_A                  | P2WSH         | [ ] | [ ] | [ ] | [ ] | **you** — Sparrow S3 optional |
| V2-04 | p2wsh_2of3_unsigned                   | P2WSH         | [ ] | [ ] | [ ] | [ ] | **you** — Sparrow S4 |
| V2-05 | p2wsh_2of3_clean (legacy)             | P2WSH         | [x] | [ ] | [ ] | [ ] | seed unknown; keep |
| V2-06 | p2sh_p2wsh_2of2                       | P2SH-P2WSH    | [ ] | [ ] | [ ] | [ ] | stretch; not V2 ship bar |

Policy (v0.3.0): **native P2WSH m-of-n cosign + finalize**. Nested multi = later.

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
