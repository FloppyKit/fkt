# FKT Phase 3 — Offline PWA

**Date:** 2026-07-09  
**Tag:** `phase3-pwa-v1`  
**File:** `pwa/index.html` (also `pwa/fkt-offline.html`)  
**Size:** ~140 KiB (≪ 1 MB) · **external network at runtime: none**

## What it does

Retro **green-on-black** single-file companion shaped like the **TUI**:

- **Main menu** (Load seed / Load PSBT / Preview / Sign / Show seed / Create wallet / Exit)
- **Pinned bottom status**: Seed + PSBT load state (emoji alerts)
- **Load screens default to QR camera scan**; button under capture: “Can’t scan? Type / browse”
- Preview (no seed) · Sign with CONFIRM · Base64 / download / dense ASCII QR

## How to run (X280 / any browser)

```bash
# offline file open (may restrict clipboard on some browsers):
xdg-open /home/dude/fkt/pwa/index.html

# or local server (still no CDN):
cd /home/dude/fkt/pwa && python3 -m http.server 8765
# browser → http://127.0.0.1:8765/
```

### Smoke test with Ice Cold / Warm mnemonic

Use the same testnet seed as CLI goldens:

```
call release rib regret puzzle magic economy tragic various embody give road
```

PSBT: `cli/tests/sparrow-real/unsigned/p2tr_1in_1out.psbt`  
(or Base64 from `cli/fktsigner base64 …`)

Warm: type the **same BIP39 words** (encrypted `.fkt` is CLI-only).

## Automated check

```bash
python3 pwa/tests/run_pwa_smoke.py
```

## Crypto (vendored offline)

Embedded MIT libraries: `@noble/secp256k1`, `@scure/bip32`, `@scure/bip39` (+ english wordlist), `qrcode-generator`.  
No `fetch` / no CDN after the file is on disk.

## Relation to CLI

| Path | Role |
|------|------|
| **Ice Cold CLI / DOS** | Max paranoia air-gap signer |
| **Warm CLI** | Encrypted seed file on isolated branch |
| **This PWA** | Offline modern companion; browser risk acknowledged |

Signing perfect first — prefer CLI for high-value keys.
