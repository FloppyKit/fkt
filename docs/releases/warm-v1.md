# FKT Warm v1 (`warm-v1`)

**Branch:** `warm-wallet` only — **never merge into `main` / Ice Cold.**  
**Date:** 2026-07-09  
**Tag:** `warm-v1`  
**Product version:** still `0.2.1` string; banner label **WARM WALLET** via `FKT_WARM_WALLET=1`.

## Purpose

Ritual / founding-cohort / education machines that need an **encrypted seed file** without polluting Ice Cold.

## Build

```bash
git checkout warm-wallet
cd cli && make warm          # clean + WARM=1
./fktsigner --version        # fkt 0.2.1
# TUI shows WARM WALLET
```

Default `make` on this branch **without** `WARM=1` remains Ice Cold (no seed-file objects linked).

## CLI

```bash
# Encrypt mnemonic → file (AES-256-GCM, PBKDF2-HMAC-SHA512, 100k iters)
./fktsigner save-seed --out ritual.fkt --seed "twelve words ..." --passphrase "secret"
# Empty passphrase allowed with LOUD stderr warnings (ritual only)

# Sign using file (preview still BEFORE seed load)
./fktsigner sign --psbt in.psbt --out out.psbt --seed-file ritual.fkt --passphrase "secret" --yes

# Optional autoload path (cwd/fkt-warm.conf or FKT_WARM_SETTINGS)
./fktsigner set-autoload ritual.fkt
./fktsigner sign --psbt in.psbt --out out.psbt --passphrase "secret" --yes
```

## File format

`FKTSEED1` | version | flags | salt(16) | nonce(12) | ct_len LE32 | ciphertext | tag(16)

## Verify

```bash
cd cli && make test-warm
```

## Hard rules

- No merge of Warm modules into `main`.
- Preview-before-seed retained.
- Real funds: prefer Ice Cold (`iced-cold-v1`) with seed typed every run.
