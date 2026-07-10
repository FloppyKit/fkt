# TESTNET-ONLY SEEDS FOR FKT TESTING

**WARNING:** These are **testnet** seeds only. **NEVER** use on mainnet.
For FKT PSBT golden-vector testing and Sparrow export only.

Last updated: 2026-07-09

---

## Nested P2SH-P2WPKH wallet

```
reward parade plug shop winner melt leg unfold sand side shell receive vague miracle day wall pear season upper monkey wear duck paper brush
```

- **Use for:** nested SegWit Sparrow fixtures (`p2sh_p2wpkh_*` in `sparrow-real/manifest.json`)
- **Env (future harness):** `FKT_SEED_NESTED`

---

## New P2WPKH wallet

```
call release rib regret puzzle magic economy tragic various embody give road
```

- **Use for:** new BIP84 P2WPKH exports under this mnemonic
- **Env (future harness):** `FKT_SEED_CALL_RELEASE`
- Master fingerprint (testnet, no passphrase): `9581fdb1`

---

## Taproot wallet

**Same mnemonic as New P2WPKH / golden-51:**

```
call release rib regret puzzle magic economy tragic various embody give road
```

- **Use for:** all prior Taproot key-path fixtures (`p2tr_*`), mixed P2WPKH+P2TR, and script-path prep fixtures
- BIP39 → 64-byte seed hex (no passphrase) matches existing harness `SEEDS["v1_p2tr"]` in `test_sparrow_real.py`
- Cannot re-preview some older wallets in Sparrow; vectors still match this seed

---

## Multisig cosigners (V2 P2WSH)

**Cosigner A** — same as New P2WPKH / Taproot:

```
call release rib regret puzzle magic economy tragic various embody give road
```

**Cosigner B** — same as Nested:

```
reward parade plug shop winner melt leg unfold sand side shell receive vague miracle day wall pear season upper monkey wear duck paper brush
```

**Cosigner C** — BIP39 test mnemonic (third key for 2-of-3 only):

```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

- **Path (synthetic + recommended Sparrow native multi):** `m/48'/1'/0'/2'/0/0`
- **Harness:** `make test-multisig`
- **Manual Sparrow checklist:** `docs/plans/2026-07-10-v2-multisig-sparrow-manual.md`

---

## Legacy P2WPKH hex (older `v1_p2wpkh_*` exports)

Older real Sparrow P2WPKH vectors were signed against a **BIP32 seed hex**, not one of the mnemonics above.
Source of truth until re-export:

- File: `cli/tests/test_sparrow_real.py` → `SEEDS["v1_p2wpkh"]`
- Env (future harness): `FKT_SEED_LEGACY_P2WPKH_HEX`

Do **not** invent a mnemonic for this hex. Prefer re-exporting under `call release…` when convenient.

---

## Usage

1. Import the appropriate mnemonic into **Sparrow testnet** (or Signet) for PSBT export.
2. Record unsigned PSBTs under `cli/tests/sparrow-real/unsigned/` and update `manifest.json`.
3. For FKT signing verification, load seed via env vars once the harness (work package 2) is wired — never hard-code mainnet seeds.

**Security:** testnet dust only. Treat these phrases as public test fixtures, not production secrets.
