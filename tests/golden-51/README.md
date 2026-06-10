# FKT Golden 51 Test Library

A deterministic corpus of 51 PSBT test vectors used to validate the
`fktsigner` binary against a known-good reference signer (Sparrow,
`embit`, or `bitcoin-cli`).

## Folder layout

```
tests/golden-51/
├── README.md                  ← this file
├── generate_golden_psbts.py   ← builds tests/golden-51/unsigned/*.psbt
├── run_golden_tests.py        ← runs fktsigner on each unsigned PSBT
│                                  and compares the output to the golden
├── unsigned/                  ← unsigned PSBTs produced by the generator
└── golden-signed/             ← reference signed PSBTs (Sparrow output)
```

`unsigned/` is regenerable from the script. `golden-signed/` is the
ground truth and must be committed; each file is produced once, by a
human, using a reference signer with the test seed below.

## Test seed (BIP-39, English wordlist, no passphrase)

```
call release rib regret puzzle magic economy tragic various embody give road
```

- master fingerprint: `9581fdb1`
- network: Bitcoin **testnet** (coin type `1`)
- always passphrase-less

All UTXOs in the corpus are synthetic: the generator builds fake
previous transactions whose outputs pay the addresses derived from the
test seed at deterministic paths. Nothing here ever touches a real
chain.

## Naming convention

```
<scripttype>[_<extra>]_<sighash>_<n>in_<n>out.psbt
```

Examples:

```
p2wpkh_all_1in_2out.psbt
p2wpkh_single_1in_2out.psbt
p2tr_keypath_default_1in_2out.psbt
p2wsh_2of3_all_1in_2out.psbt
p2sh_p2wpkh_all_1in_2out.psbt
mixed_p2wpkh_p2tr_1in_each.psbt
```

Sighash codes used in filenames:

| code            | byte value | meaning                  |
| --------------- | ---------- | ------------------------ |
| `default`       | `0x00`     | Taproot default (== ALL) |
| `all`           | `0x01`     | SIGHASH_ALL              |
| `none`          | `0x02`     | SIGHASH_NONE             |
| `single`        | `0x03`     | SIGHASH_SINGLE           |
| `acp`           | `0x80`     | ANYONECANPAY (combined)  |
| `all_acp`       | `0x81`     | ALL \| ANYONECANPAY      |
| `single_acp`    | `0x83`     | SINGLE \| ANYONECANPAY   |

## Categories and current FKT coverage

| category             | count | FKT V1.0  | notes                          |
| -------------------- | ----- | --------- | ------------------------------ |
| p2wpkh               | 10    | full      | BIP-84, ECDSA, BIP-143         |
| p2wsh (multisig)     |  8    | deferred  | V1.5+; structural only         |
| p2sh-p2wpkh          |  5    | deferred  | V1.5+; structural only         |
| p2sh-p2wsh           |  5    | deferred  | V1.5+; structural only         |
| p2tr keypath         | 12    | full      | BIP-86, BIP-341 key-path       |
| mixed / edge         | 11    | partial   | mixed inputs and odd flags     |
| **total**            | **51**|           |                                |

"Full" means the FKT signer should sign the PSBT and produce output
that matches the reference byte-for-byte (deterministic ECDSA / Schnorr
nonces guarantee reproducibility).

"Deferred" means the unsigned PSBT is generated for completeness, but
the FKT signer is not expected to produce a valid signature in V1.0;
the runner reports these as **xfail** (expected to fail) and tracks
them so they light up green automatically once V1.5 lands.

## How to use

### 1. Install dependencies

```
pip install embit
```

`embit` is the only third-party requirement. It's already used by other
scripts in this repo.

### 2. Generate the unsigned corpus

```
cd tests/golden-51
python3 generate_golden_psbts.py
```

This populates `unsigned/` with 51 deterministic PSBT files. The files
are reproducible: re-running the script always produces the same bytes.

### 3. Produce the golden-signed reference (one-time, manual)

#### Recommended signing order

The 51 cases break down into 26 V1.0-passing and 25 deferred. Don't
sign all 26 at once — that's a lot of clicking in Sparrow with no
intermediate validation. Sign in tiered batches, run
`run_golden_tests.py` after each batch, fix anything that fails before
moving to the next tier. This way every regression has a small blast
radius.

Tier 1 — bedrock baselines (5). Sign these first. If any fail, stop
and debug before going further.

| # | case | exercises |
|---|------|-----------|
| 1 | `p2wpkh_all_1in_2out` | minimal P2WPKH ECDSA, SIGHASH_ALL, BIP-143 |
| 2 | `p2tr_keypath_default_1in_2out` | minimal P2TR Schnorr, SIGHASH_DEFAULT, BIP-341 |
| 3 | `p2wpkh_all_2in_2out` | multi-input ECDSA loop |
| 4 | `p2tr_keypath_default_2in_2out` | multi-input Schnorr loop |
| 5 | `p2wpkh_all_1in_1out` | no-change-output path |

Tier 2 — sighash variants (3). Validates the BIP-143 SIGHASH_SINGLE
fix and the explicit-byte sighash trailer write.

| # | case | exercises |
|---|------|-----------|
| 6 | `p2wpkh_single_1in_2out` | BIP-143 SIGHASH_SINGLE rules (zero hashSequence, single hashOutputs) |
| 7 | `p2tr_keypath_single_1in_2out` | BIP-341 SIGHASH_SINGLE |
| 8 | `p2tr_keypath_all_1in_2out` | explicit `0x01` sighash byte vs default `0x00` |

Tier 3 — output / locktime variants (3). Catches off-by-one bugs in
varint counts and locktime serialization.

| # | case | exercises |
|---|------|-----------|
|  9 | `p2wpkh_locktime_1in_2out` | non-zero `nLocktime` little-endian write |
| 10 | `p2wpkh_all_1in_3out` | hashOutputs varint count > 2 |
| 11 | `p2tr_keypath_to_p2wpkh_1in_1out` | Taproot input paying to non-Taproot output |

Tier 4 — cross-type (1). Exercises the Taproot key-path auto-detect
alongside ECDSA in the same transaction.

| # | case | exercises |
|---|------|-----------|
| 12 | `mixed_p2wpkh_p2tr_2in_2out` | per-input dispatch between BIP-143 and BIP-341 |

After Tier 4, `run_golden_tests.py` should report 12 PASS / 14 SKIP
(remaining V1-passing) / 25 SKIP (xfail). Continue with the remaining
14 V1-passing cases (dust, high-locktime, final-seq, both-utxos,
non-witness-only, 3-in-1-out, etc.) in any order — they exercise
fewer new code paths and are mostly stress-test variants.

Edge cases that Sparrow will refuse: `p2wpkh_zero_fp_1in_2out` cannot
be signed in Sparrow (its fingerprint doesn't match any wallet);
generate that golden via the `embit` snippet below instead.

#### General procedure (per case)

For each `unsigned/<name>.psbt`:

1. Open Sparrow Wallet (testnet mode).
2. Load a watch-only wallet for the test seed (or a hot wallet if you
   trust your machine — this seed has no value).
3. File → Open Transaction → load `unsigned/<name>.psbt`.
4. Sign it with the test seed.
5. File → Save Transaction (Finalized PSBT) →
   `golden-signed/<name>.psbt`.

For categories where Sparrow refuses to sign (e.g. `none`, `acp`
variants), use `embit`'s `tx.sign_with(key)` instead — it will sign
anything cryptographically valid:

```python
from embit import bip39, bip32, psbt, networks
seed = bip39.mnemonic_to_seed("call release ...")
root = bip32.HDKey.from_seed(seed, version=networks.NETWORKS["test"]["xprv"])
tx = psbt.PSBT.parse(open("unsigned/<name>.psbt","rb").read())
tx.sign_with(root)
open("golden-signed/<name>.psbt","wb").write(tx.serialize())
```

### 4. Run the test suite

```
cd tests/golden-51
python3 run_golden_tests.py [--fktsigner ../../fktsigner]
```

The runner:
1. iterates every file in `unsigned/` that has a counterpart in
   `golden-signed/`,
2. invokes `fktsigner sign <unsigned> <tmp_out> "<seed>"`,
3. compares `<tmp_out>` to `golden-signed/<name>.psbt`,
4. prints a one-line PASS / FAIL / XFAIL / XPASS / SKIP per case,
5. exits non-zero if any case is in unexpected state.

### Comparison rules

For each case, the runner currently performs an exact byte
comparison of the FKT-produced output against the golden. ECDSA
(RFC 6979) and Schnorr (BIP-340) are deterministic, so identical seed
+ identical PSBT must produce identical bytes.

If a case ever fails an exact match, the runner falls back to a
field-level comparison: it parses both PSBTs and compares only the
signature-bearing fields (`PSBT_IN_PARTIAL_SIG = 0x02`,
`PSBT_IN_TAP_KEY_SIG = 0x13`, `PSBT_IN_FINAL_SCRIPTWITNESS = 0x08`).
Differences in metadata (e.g. proprietary keys added by Sparrow) are
surfaced as warnings, not failures.

## Determinism guarantees

- prevout txids are derived from
  `sha256d("FKT_GOLDEN_51:" + case_name + ":" + index)` so they're
  reproducible without ever broadcasting anything.
- amounts are fixed at 100_000 sat per input unless the case name says
  otherwise (`dust` ⇒ 546 sat, etc.).
- locktimes are 0 unless the case name says otherwise.
- sequence is `0xfffffffd` (RBF-signaling) by default.

## Adding cases

1. Append a `Case(...)` entry to the `CASES` list in
   `generate_golden_psbts.py`.
2. Re-run the generator.
3. Produce the matching golden in `golden-signed/`.
4. Re-run the test suite.

Keep the case count at 51 unless we have a strong reason to grow it —
51 is the project's working ceiling for V1.0.

## When a test fails

- **xfail → fail (red):** a deferred category (multisig etc.)
  unexpectedly broke. Look at the `Case.notes` field for context.
- **pass → fail (red):** a category that used to work has regressed.
  Run with `--verbose` to see the field-level diff.
- **xfail → xpass (yellow):** a deferred category started signing
  correctly. Time to upgrade its expectation in the case table.

## License

Same as the rest of the FKT project (MIT-style).
