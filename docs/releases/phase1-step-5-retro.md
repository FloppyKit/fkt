# FKT Phase 1 Step 5 — Retro DOS build + floppy package

**Date:** 2026-07-09  
**Tag:** `phase1-step-5-retro`  
**Version string:** `0.2.1` (Ice Cold product string; see `iced-cold-v1`)

## Packaging (canonical)

| Medium | Build | Artifact | Budget |
|--------|-------|----------|--------|
| **1.44 MB floppy** | `make -f Makefile.dos` | `FKTSIGN.EXE` + `CWSDPMI.EXE` | **Applies** |
| **Bootable USB / GUI** | `make` (Linux) | `fktsigner` in tiny live Linux | Host basis; not floppy budget |

## Size audit (this step)

| File | Bytes | Notes |
|------|------:|-------|
| `FKTSIGN.EXE` (stripped) | 296 448 | ~290 KiB; soft cap 1.20 MiB |
| `CWSDPMI.EXE` | 21 325 | DJGPP DPMI host |
| `README.TXT` | ~2 040 | from `cli/docs/DOS_README.TXT` |
| **Package total** | **~320 KB** | **~21% of 1.44 MB** |

```bash
# rebuild + stage + audit
./scripts/stage_floppy.sh
# → dist/floppy-iced-cold/{FKTSIGN.EXE,CWSDPMI.EXE,README.TXT,VERSION.TXT}

./scripts/check_floppy_size.sh dist/floppy-iced-cold/FKTSIGN.EXE
./scripts/check_floppy_size.sh --package dist/floppy-iced-cold
```

## DOSBox smoke (automated)

```text
FKTSIGN.EXE --version  →  fkt 0.2.1
```

(Host: DOSBox 0.74; mount staged package dir as `C:`.)

Manual TUI QA still open for Matt (see `cli/docs/DOS_TEST_STATUS.txt`).

## Build

```bash
export PATH="$PWD/tools/djgpp/bin:$PATH"
export LD_LIBRARY_PATH="$PWD/tools/djgpp/lib/host:$LD_LIBRARY_PATH"
cd cli && make -f Makefile.dos          # stripped FKTSIGN.EXE
cd .. && ./scripts/stage_floppy.sh      # package under dist/
```

Requires prebuilt `secp256k1-build-dos/libsecp256k1.a` (already in tree for this host).

## Linux note

Unstripped host `fktsigner` remains ~1.5 MB and is **not** the floppy deliverable. USB live image will ship a stripped Linux binary separately.
