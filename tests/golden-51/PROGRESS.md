# Golden 51 — Progress Tracker

Last updated: May 6, 2026 — 20/22 V1 goldens signed, PASS=5 after finalizer fix.

**Status: 20/22 V1 cases signed as of May 6, 2026.**

This file is a living spreadsheet. Update by hand as each
`golden-signed/<name>.psbt` lands, or recompute with:

```
ls tests/golden-51/golden-signed/*.psbt 2>/dev/null | wc -l
```

## Quick stats

| pool                   | count | signed |
|------------------------|------:|-------:|
| Tier 1 (bedrock)       |  5    |  5     |
| Tier 2 (sighash)       |  3    |  3     |
| Tier 3 (shape/locktime)|  3    |  3     |
| Tier 4 (cross-type)    |  0    |  0     |
| Tier 5 (remaining V1)  | 11    |  9     |
| **V1 sub-total**       | **22**| **20** |
| V1-deferred (Sparrow)  |  4    |  0     |
| xfail (V1.5+)          | 25    |  0     |
| **Total**              | **51**| **20** |

## Legend

- **Tier** — signing order priority (T1 first, T5 last; "—" = not on the V1 path).
- **Expected** — what `run_golden_tests.py` should report once a golden lands. `PASS` means FKT must produce byte-identical output. `XFAIL` means we expect FKT to refuse or mismatch in V1.0.
- **Current** — local tracker state:
  - `Pending` — unsigned, no golden yet
  - `Signed` — golden file present in `golden-signed/`
  - `xfail` — deferred; do not sign in V1.0
  - `Sparrow-blocked` — Sparrow cannot produce this golden; use `embit` snippet from README §3
- To flip a row to `Signed`, edit the cell **and** bump the matching count in the Quick Stats table above.

## V1-supported (22)

### Tier 1 — bedrock baselines (5)

| # | Case Name                              | Tier | Expected | Current |
|--:|----------------------------------------|------|----------|---------|
| 1 | `p2wpkh_all_1in_2out`                  | T1   | PASS     | Signed  |
| 2 | `p2tr_keypath_default_1in_2out`        | T1   | PASS     | Signed  |
| 3 | `p2wpkh_all_2in_2out`                  | T1   | PASS     | Signed  |
| 4 | `p2tr_keypath_default_2in_2out`        | T1   | PASS     | Signed  |
| 5 | `p2wpkh_all_1in_1out`                  | T1   | PASS     | Signed  |

### Tier 2 — sighash variants (3)

| # | Case Name                              | Tier | Expected | Current |
|--:|----------------------------------------|------|----------|---------|
| 6 | `p2wpkh_single_1in_2out`               | T2   | PASS     | Signed  |
| 7 | `p2tr_keypath_single_1in_2out`         | T2   | PASS     | Signed  |
| 8 | `p2tr_keypath_all_1in_2out`            | T2   | PASS     | Signed  |

### Tier 3 — output / locktime variants (3)

|  # | Case Name                              | Tier | Expected | Current |
|---:|----------------------------------------|------|----------|---------|
|  9 | `p2wpkh_locktime_1in_2out`             | T3   | PASS     | Signed  |
| 10 | `p2wpkh_all_1in_3out`                  | T3   | PASS     | Signed  |
| 11 | `p2tr_keypath_to_p2wpkh_1in_1out`      | T3   | PASS     | Signed  |

### Tier 4 — cross-type (0)

The original T4 case (`mixed_p2wpkh_p2tr_2in_2out`) moved to
**V1-deferred** on May 6, 2026 because Sparrow can't load BIP-84 and
BIP-86 wallets in one signing pass to cover both inputs at once.
Re-add a T4 case here if/when you find a Sparrow workflow that handles
the cross-type case in a single sign action.

### Tier 5 — remaining V1-supported (11, sign last)

|  # | Case Name                              | Tier | Expected | Current |
|---:|----------------------------------------|------|----------|---------|
| 12 | `p2wpkh_all_3in_2out`                  | T5   | PASS     | Signed  |
| 13 | `p2wpkh_dust_1in_2out`                 | T5   | PASS     | Signed  |
| 14 | `p2wpkh_final_seq_1in_2out`            | T5   | PASS     | Signed  |
| 15 | `p2wpkh_consolidate_3in_1out`          | T5   | PASS     | Signed  |
| 16 | `p2tr_keypath_default_3in_2out`        | T5   | PASS     | Signed  |
| 17 | `p2tr_keypath_default_1in_3out`        | T5   | PASS     | Pending |
| 18 | `p2tr_keypath_default_1in_1out`        | T5   | PASS     | Pending |
| 19 | `p2tr_keypath_dust_1in_2out`           | T5   | PASS     | Signed  |
| 20 | `p2tr_keypath_locktime_1in_2out`       | T5   | PASS     | Signed  |
| 21 | `p2tr_keypath_consolidate_3in_1out`    | T5   | PASS     | Signed  |
| 22 | `p2wpkh_high_locktime_1in_2out`        | T5   | PASS     | Signed  |

## V1-deferred — Sparrow-quirky (4)

FKT signs these correctly, but Sparrow either cannot or will not
produce the reference bytes. Generate these goldens with the `embit`
snippet documented in [README.md](README.md) §3, then move to
`Signed`. Do them after the 22 above — they verify nothing new about
FKT's signer, only the runner's tolerance.

|  # | Case Name                              | Tier | Expected | Current        |
|---:|----------------------------------------|------|----------|----------------|
| 23 | `p2wpkh_zero_fp_1in_2out`              |  —   | PASS     | Sparrow-blocked|
| 24 | `p2wpkh_nonwitness_only_1in_2out`      |  —   | PASS     | Pending        |
| 25 | `p2wpkh_both_utxos_1in_2out`           |  —   | PASS     | Pending        |
| 26 | `mixed_p2wpkh_p2tr_2in_2out`           |  —   | PASS     | Pending        |

## Deferred to V1.5+ (xfail, 25)

These are structural-only PSBTs in the corpus — they exist so V1.5
multisig / P2SH-wrapped / ANYONECANPAY work flips them green
automatically. Do **not** sign in V1.0. The runner will report XFAIL
either way (signer refuses or output differs from any golden).

|  # | Case Name                                  | Tier | Expected | Current |
|---:|--------------------------------------------|------|----------|---------|
| 27 | `p2wpkh_none_1in_2out`                     |  —   | XFAIL    | xfail   |
| 28 | `p2wpkh_all_acp_1in_2out`                  |  —   | XFAIL    | xfail   |
| 29 | `p2tr_keypath_none_1in_2out`               |  —   | XFAIL    | xfail   |
| 30 | `p2tr_keypath_all_acp_1in_2out`            |  —   | XFAIL    | xfail   |
| 31 | `p2sh_p2wpkh_all_1in_2out`                 |  —   | XFAIL    | xfail   |
| 32 | `p2sh_p2wpkh_all_2in_2out`                 |  —   | XFAIL    | xfail   |
| 33 | `p2sh_p2wpkh_single_1in_2out`              |  —   | XFAIL    | xfail   |
| 34 | `p2sh_p2wpkh_all_acp_1in_2out`             |  —   | XFAIL    | xfail   |
| 35 | `p2sh_p2wpkh_locktime_1in_2out`            |  —   | XFAIL    | xfail   |
| 36 | `p2wsh_1of1_all_1in_2out`                  |  —   | XFAIL    | xfail   |
| 37 | `p2wsh_2of2_all_1in_2out`                  |  —   | XFAIL    | xfail   |
| 38 | `p2wsh_2of3_all_1in_2out`                  |  —   | XFAIL    | xfail   |
| 39 | `p2wsh_3of5_all_1in_2out`                  |  —   | XFAIL    | xfail   |
| 40 | `p2wsh_2of3_all_2in_2out`                  |  —   | XFAIL    | xfail   |
| 41 | `p2wsh_2of3_single_1in_2out`               |  —   | XFAIL    | xfail   |
| 42 | `p2wsh_2of3_all_acp_1in_2out`              |  —   | XFAIL    | xfail   |
| 43 | `p2wsh_2of3_all_3in_2out`                  |  —   | XFAIL    | xfail   |
| 44 | `p2sh_p2wsh_1of1_all_1in_2out`             |  —   | XFAIL    | xfail   |
| 45 | `p2sh_p2wsh_2of2_all_1in_2out`             |  —   | XFAIL    | xfail   |
| 46 | `p2sh_p2wsh_2of3_all_1in_2out`             |  —   | XFAIL    | xfail   |
| 47 | `p2sh_p2wsh_2of3_all_2in_2out`             |  —   | XFAIL    | xfail   |
| 48 | `p2sh_p2wsh_2of3_single_1in_2out`          |  —   | XFAIL    | xfail   |
| 49 | `mixed_p2wpkh_p2sh_p2wpkh_2in_2out`        |  —   | XFAIL    | xfail   |
| 50 | `mixed_p2wsh_p2tr_2in_2out`                |  —   | XFAIL    | xfail   |
| 51 | `mixed_p2sh_p2wpkh_p2tr_2in_2out`          |  —   | XFAIL    | xfail   |

## Update workflow (per-case)

1. Open `unsigned/<name>.psbt` in Sparrow, sign, save as `golden-signed/<name>.psbt`.
2. From `tests/golden-51/`: `python3 run_golden_tests.py --filter <name>` — confirm `PASS`.
3. Open this file, change the row's **Current** cell from `Pending` → `Signed`.
4. Bump the matching tier counter in the Quick Stats table.
5. Once all rows in a tier flip, run the full suite to make sure nothing regressed:
   `python3 run_golden_tests.py`.

## Discrepancy log

If a case lands as `FAIL` instead of `PASS`, add a line below before fixing:

```
- <date>  <case>  -- <one-line root cause>
```

(Empty until something fails.)
