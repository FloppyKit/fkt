# FKT Ice Cold v1 (`iced-cold-v1`)

**Date:** 2026-07-09  
**Git tag:** `iced-cold-v1`  
**Product version string:** `0.2.1` (`FKT_VERSION_STRING` / banner / `--version`)  
**Branch:** `main`  
**Profile:** Ice Cold only — stateless, seed every run, no seed-file paths.

## What ships

| Deliverable | Location |
|-------------|----------|
| DOS floppy package | `dist/floppy-iced-cold/` (`FKTSIGN.EXE` + `CWSDPMI.EXE` + `README.TXT`) |
| Linux host signer | `cd cli && make` → `fktsigner` (USB/GUI basis later) |
| Full test umbrella | `cd cli && make test` |
| Retro gate | `cd cli && make test-retro` |

## Phase 1 gates (complete)

1. Proprietary BIP174 `0xFC` passthrough (global/input/output)  
2. Modular PSBT core (P2WPKH + Taproot keypath + 0xFC)  
3. CLI entry: preview → seed → sign → binary + Base64 + optional QR  
4. Full suite: BIP vectors, Sparrow matrix, multi-input, SP stub  
5. DOS build + size audit (~21% of 1.44 MB) + DOSBox smoke  
6. This tag  

## Verify

```bash
cd cli && make test
export PATH="$PWD/../tools/djgpp/bin:$PATH"
export LD_LIBRARY_PATH="$PWD/../tools/djgpp/lib/host:$LD_LIBRARY_PATH"
make test-retro
# Banner / version:
./fktsigner --version          # fkt 0.2.1
# DOS package:
#   FKTSIGN.EXE --version      # fkt 0.2.1
#   TUI banner: FKT SIGNER v0.2.1
```

## Packaging reminder

- **Floppy** = DOS `FKTSIGN.EXE`  
- **USB / GUI** = Linux `fktsigner` in a tiny secure live environment (not this tag’s scope)

## Explicitly not in Ice Cold v1

- Warm encrypted seed file (Phase 2, isolated branch only)  
- Offline PWA (Phase 3)  
- Nostr coordinator / mock relay (Phase 4+)  
- Silent Payments scan/spend (stub only)  
