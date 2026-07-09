# Sparrow real PSBT matrix (testnet)

Structured golden vectors for **FKT CLI signing** validation against real Sparrow exports.

Plan: `docs/plans/2026-07-09-post-v0.1-sparrow-and-ark-offline.md`  
Tag: `plan/2026-07-09-post-v0.1-test-matrix`  
Seeds: `cli/tests/TEST_SEEDS.md` (**TESTNET ONLY**)

---

## Layout (skill-aligned)

```
cli/tests/sparrow-real/
├── README.md              ← this file
├── manifest.json          ← source of truth for cases / expect / seeds
├── unsigned/              ← canonical unsigned PSBTs (id.psbt)
├── sparrow-signed/        ← Sparrow reference signed PSBTs (when present)
├── fkt-signed/            ← FKT-signed **goldens** (high+medium+low; harness regenerates)
├── Unsigned/v1/           ← legacy tree (kept for old harness / history)
├── Signed/v1/             ← legacy Sparrow-signed tree
└── output/                ← legacy harness scratch (do not treat as golden)
```

| Skill name | Path |
|------------|------|
| unsigned | `unsigned/` |
| sparrow-signed | `sparrow-signed/` |
| fkt-signed | `fkt-signed/` |
| manifest | `manifest.json` |

Legacy `Unsigned/v1/` and `Signed/v1/` remain until the sign/reject harness fully migrates. Each manifest case records `legacy_source`.

---

## Manifest schema (per case)

```json
{
  "id": "p2wpkh_1in_1out",
  "unsigned": "unsigned/p2wpkh_1in_1out.psbt",
  "sparrow_signed": "sparrow-signed/p2wpkh_1in_1out.psbt",
  "fkt_signed": "fkt-signed/p2wpkh_1in_1out.psbt",
  "expect": "sign",
  "script": "p2wpkh",
  "priority": "high",
  "seed_ref": "legacy_p2wpkh_hex",
  "seed_env": "FKT_SPARROW_SEED",
  "notes": "..."
}
```

**`expect` values**

| Value | Meaning |
|-------|---------|
| `sign` | FKT must produce a valid signature set for matching keys |
| `reject` | FKT must hard-abort / non-zero with a known error class |
| `partial_sig` | May add partial sigs; must not claim full finalize support |

---

## Policy (v0.1 product)

Documented in `manifest.json` → `policy`:

| Script | Policy |
|--------|--------|
| Nested P2SH-P2WPKH | **sign if key matches** (code path exists) |
| P2WSH multisig | **partial_sig only** — not fully supported |
| Taproot script-path | Current named fixtures are **keypath** (sign). True script-path (0x18/0x15) → 0.2 + version bump |

---

## Running the harness

```bash
cd cli
make                    # build fktsigner + verify_ecdsa
make test-sparrow-real  # high + medium + low (sign/reject)
make test-sparrow-real ARGS=--all
make test-sparrow-real-list   # fixtures only, no signing

# Optional seed overrides (mnemonic or 128-char hex):
export FKT_SEED_CALL_RELEASE="call release rib regret ..."
export FKT_SEED_NESTED="reward parade plug shop ..."
export FKT_SEED_LEGACY_P2WPKH_HEX="<128 hex chars>"
```

Outputs land in `fkt-signed/`. **Default-matrix goldens are committed** (14 files).
Pass criteria: signer success + signature material; byte-equal to Sparrow when
possible; else ECDSA verify (`verify_ecdsa`) for P2WPKH legs; Taproot keypath
witness structure / Sparrow witness match.

```bash
make test-sparrow-real-golden   # sign + require byte-stable goldens
```

---

## High-priority matrix

List anytime with:

```bash
cd cli && make test-sparrow-real-list
# or: python3 tests/sparrow_real_list.py
```

| id | expect | seed_ref | notes |
|----|--------|----------|-------|
| `p2wpkh_1in_1out` | sign | legacy_p2wpkh_hex | BIP84 baseline |
| `p2wpkh_2in_2out` | sign | legacy_p2wpkh_hex | Multi-in + change |
| `p2wpkh_rbf` | sign | legacy_p2wpkh_hex | RBF |
| `p2wpkh_locktime` | sign | legacy_p2wpkh_hex | Locktime |
| `p2wpkh_with_change` | sign | legacy_p2wpkh_hex | Alias of 2in_2out |
| `p2tr_1in_1out` | sign | call_release | BIP86 key-path |
| `p2tr_2in_2out` | sign | call_release | Multi-in TR |
| `p2tr_rbf` | sign | call_release | RBF + TR |
| `mixed_p2wpkh_p2tr_2in_2out` | sign | call_release | **Critical mixed** |

**Present and prioritized next (medium / prep):**

- Nested: `p2sh_p2wpkh_1in_1out` (+ rbf/locktime/anyonecanpay variants)
- Script-path prep: `p2tr_script_path` (`expect=reject` until 0.2)
- Mixed variants: rbf-off, locktime-on, all-anyonecanpay

---

## Seeds (testnet only)

See `cli/tests/TEST_SEEDS.md`. Summary:

| seed_ref | Kind | Purpose |
|----------|------|---------|
| `call_release` | BIP39 | Taproot, mixed, new P2WPKH, script-path fixtures |
| `nested_reward_parade` | BIP39 | Nested P2SH-P2WPKH |
| `legacy_p2wpkh_hex` | hex | Older `v1_p2wpkh_*` only |

---

## Work package status

| Package | Status |
|---------|--------|
| 1 Layout + manifest + README | done (`test-matrix-step-1-layout-complete`) |
| 2 Sign/reject harness against env seed | done (`test-matrix-step-2-harness-complete`) |
| 3 FKT-signed goldens + checklist | **this commit** |
| Script-path signing (0.2) | later — true 0x18/0x15 fixtures; version bump when support lands |

---

## Adding a case

1. Export unsigned (and ideally Sparrow-signed) PSBT from Sparrow **testnet**.
2. Copy to `unsigned/<id>.psbt` and `sparrow-signed/<id>.psbt`.
3. Append an entry to `manifest.json` (`priority`, `expect`, `seed_ref`, `notes`).
4. Do not commit mainnet seeds or funded mainnet UTXOs.
