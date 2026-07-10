# Sparrow manual test vectors — V2 P2WSH multisig

**Product:** FKT ≥ 0.3.0  
**Network:** **TESTNET or SIGNET only**  
**Goal:** Real Sparrow multi wallets that FKT can cosign / finalize.

Automated synthetic coverage already exists (`make test-multisig`).  
These are the **human Sparrow exports** to land under `cli/tests/sparrow-real/` when you have time.

---

## Seeds (TESTNET ONLY — public fixtures)

| Role | Mnemonic | Notes |
|------|----------|--------|
| **Cosigner A** | `call release rib regret puzzle magic economy tragic various embody give road` | Same as P2TR / P2WPKH “call release” |
| **Cosigner B** | `reward parade plug shop winner melt leg unfold sand side shell receive vague miracle day wall pear season upper monkey wear duck paper brush` | Same as nested wallet |
| **Cosigner C** | `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about` | BIP39 test vector; third key for 2-of-3 |

**Derivation (Sparrow native multi, match synthetic):**  
`m/48'/1'/0'/2'/0/0` per cosigner (BIP48 script type 2 = P2WSH, coin_type 1 = testnet).

In Sparrow: **Settings → New Wallet → Multi Signature** → Native Segwit (P2WSH) → add xpubs from A/B/(C) with that path policy (or import standard multi descriptor Sparrow builds for BIP48).

---

## Vectors to create (exact checklist)

Drop unsigned PSBTs into:

`cli/tests/sparrow-real/unsigned/`

| # | Filename | Policy | Cosigners in wallet | What you do in Sparrow | FKT expect | How to test |
|---|----------|--------|---------------------|------------------------|------------|-------------|
| **S1** | `p2wsh_1of1_sparrow.psbt` | **1-of-1** | A only | Fund multi receive → spend 1-in → **Export unsigned PSBT** (do not sign in Sparrow) | **sign + finalize** in one FKT run with seed A | Below |
| **S2** | `p2wsh_2of2_unsigned.psbt` | **2-of-2** | A + B | Same; export **fully unsigned** (no Sparrow signatures) | A → partial; B → finalize | Below |
| **S3** | `p2wsh_2of2_partial_A.psbt` | **2-of-2** | A + B | Optional: sign with A **in Sparrow**, export PSBT still needing B | FKT with seed B → finalize | Below |
| **S4** | `p2wsh_2of3_unsigned.psbt` | **2-of-3** | A + B + C | Export unsigned 1-in spend | A partial; B finalize (C unused) | Below |
| **S5** | `p2wsh_2of3_partial_AC.psbt` | **2-of-3** | A + B + C | Optional: Sparrow signs A (and maybe C); still need one more | FKT with B → finalize | Optional |
| **S6** | `p2sh_p2wsh_2of2_unsigned.psbt` | **2-of-2 nested** | A + B | Nested multi if you want stretch | **May fail / partial only** today — document result | Stretch |

**Minimum bar for “Sparrow green”:** **S1 + S2 + S4**.

---

## Step-by-step: create each kind

### Common Sparrow setup

1. Sparrow → **Testnet** (or Signet) server.  
2. Create **three** software wallets (or xpubs only) from mnemonics **A**, **B**, **C** above.  
3. Create multi wallet(s):

| Wallet name | Quorum | Key order |
|-------------|--------|-----------|
| `fkt-ms-1of1` | 1 of 1 | A |
| `fkt-ms-2of2` | 2 of 2 | A, B (BIP67 sorted OK — Sparrow does this) |
| `fkt-ms-2of3` | 2 of 3 | A, B, C |

4. Prefer **Native Segwit (P2WSH)** multi.  
5. Fund the multi **receive** address with a tiny testnet amount (any faucet → send to multi).  
6. Wait for confirmation.

### S1 — 1-of-1 unsigned

1. Open `fkt-ms-1of1`.  
2. Send almost all to any testnet address you control (leave fee).  
3. **Do not sign** in Sparrow if you can export unsigned; else: create tx → **Save transaction** / **Export PSBT** before signing.  
4. Save as:  
   `cli/tests/sparrow-real/unsigned/p2wsh_1of1_sparrow.psbt`  
5. Confirm PSBT has:  
   - `PSBT_IN_WITNESS_UTXO`  
   - `PSBT_IN_WITNESS_SCRIPT` (0x05) with `OP_1 <A> OP_1 OP_CHECKMULTISIG`  
   - `PSBT_IN_BIP32_DERIVATION` for A  

**FKT test:**

```bash
cd cli
./fktsigner sign \
  --psbt tests/sparrow-real/unsigned/p2wsh_1of1_sparrow.psbt \
  --out tests/sparrow-real/fkt-signed/p2wsh_1of1_sparrow.psbt \
  --seed "call release rib regret puzzle magic economy tragic various embody give road" \
  --yes
```

**Pass:** exit 0; input status shows finalized / final_scriptwitness present; Sparrow can **Load** signed PSBT and broadcast.

---

### S2 — 2-of-2 fully unsigned

1. Open `fkt-ms-2of2`, create spend, **export unsigned PSBT** (no signatures).  
2. Save:  
   `cli/tests/sparrow-real/unsigned/p2wsh_2of2_unsigned.psbt`  

**FKT test (two passes):**

```bash
cd cli
# Cosigner A
./fktsigner sign \
  --psbt tests/sparrow-real/unsigned/p2wsh_2of2_unsigned.psbt \
  --out /tmp/2of2_after_A.psbt \
  --seed "call release rib regret puzzle magic economy tragic various embody give road" \
  --yes
# Expect: PARTIAL (one partial_sig), not fully finalized

# Cosigner B
./fktsigner sign \
  --psbt /tmp/2of2_after_A.psbt \
  --out tests/sparrow-real/fkt-signed/p2wsh_2of2_unsigned.psbt \
  --seed "reward parade plug shop winner melt leg unfold sand side shell receive vague miracle day wall pear season upper monkey wear duck paper brush" \
  --yes
# Expect: FINALIZED
```

**Pass:** Sparrow loads final PSBT → broadcasts.

---

### S3 — 2-of-2 already partial from Sparrow (optional)

1. Same wallet; create spend; **sign only with A in Sparrow** (or sign A on another machine).  
2. Export PSBT that still needs B.  
3. Save:  
   `cli/tests/sparrow-real/unsigned/p2wsh_2of2_partial_A.psbt`  

```bash
./fktsigner sign \
  --psbt tests/sparrow-real/unsigned/p2wsh_2of2_partial_A.psbt \
  --out tests/sparrow-real/fkt-signed/p2wsh_2of2_partial_A.psbt \
  --seed "reward parade plug shop winner melt leg unfold sand side shell receive vague miracle day wall pear season upper monkey wear duck paper brush" \
  --yes
```

**Pass:** FKT finalizes without re-signing A.

---

### S4 — 2-of-3 fully unsigned

1. Open `fkt-ms-2of3`, export **unsigned** spend PSBT.  
2. Save:  
   `cli/tests/sparrow-real/unsigned/p2wsh_2of3_unsigned.psbt`  

```bash
./fktsigner sign --psbt tests/sparrow-real/unsigned/p2wsh_2of3_unsigned.psbt \
  --out /tmp/2of3_A.psbt \
  --seed "call release rib regret puzzle magic economy tragic various embody give road" --yes

./fktsigner sign --psbt /tmp/2of3_A.psbt \
  --out tests/sparrow-real/fkt-signed/p2wsh_2of3_unsigned.psbt \
  --seed "reward parade plug shop winner melt leg unfold sand side shell receive vague miracle day wall pear season upper monkey wear duck paper brush" --yes
# C never used — threshold 2
```

**Pass:** finalized; Sparrow broadcast OK.

---

### S6 — Nested P2SH-P2WSH (stretch only)

1. Sparrow multi as **Nested Segwit (P2SH-P2WSH)** 2-of-2.  
2. Export unsigned.  
3. Try FKT with A then B.  
4. **Document result** (pass / partial / reject). Not required for V2 ship bar.

---

## What each PSBT must contain (sanity)

| Field | Required |
|-------|----------|
| Global unsigned tx | yes |
| Per input `witness_utxo` | yes (or non-witness + consistency) |
| Per input `witness_script` | bare `OP_m <pubs…> OP_n OP_CHECKMULTISIG` |
| Per input `bip32_derivation` | **one entry per cosigner key** you expect FKT to match |
| Sorted multi pubs | Sparrow BIP67 — fine |

If BIP32 paths are missing for your cosigner, FKT cannot match the key → “Wrong seed”.

---

## After you have the files

1. Copy into `unsigned/` as named above.  
2. Optional: add rows to `cli/tests/sparrow-real/manifest.json` with `expect: sign` / `partial_sig` and `seed_ref`.  
3. Tell the agent: *“Sparrow multi vectors dropped — wire harness.”*  
4. Keep amounts tiny; never use these seeds on mainnet.

---

## Already automated (you do **not** need Sparrow for these)

```bash
cd cli && make test-multisig
```

| Synthetic | Seeds | Result |
|-----------|-------|--------|
| 1-of-1 | A | finalize |
| 2-of-2 | A then B | partial → finalize |
| 2-of-3 | A then B | partial → finalize |
| 2-of-2 | C only | reject |

Generator: `cli/tests/gen_multisig_vector.c`  
Path: `m/48'/1'/0'/2'/0/0`
