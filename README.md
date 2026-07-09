# ⚠️ FKT — Floppy Kit (EARLY / MESSY / EXPERIMENTAL)

This is pre-alpha work-in-progress code for an air-gapped Bitcoin PSBT signer.

**Do not use with real funds. Do not treat as production ready.**

The codebase is currently being cleaned and refactored. Expect chaos, incomplete features, and ugly structure.

Feedback and brutal code review welcome.

# FKT — Floppy Kit

> **⚠️ PRE-ALPHA / HEAVY DEVELOPMENT / TESTNET ONLY**  
> This is early, actively changing code.  
> **Do not use with real Bitcoin.** Testnet and dummy data only.  
> Expect breaking changes, incomplete features, and rough edges.  
> Feedback, test vectors, and brutal review are very welcome.

**Will it bitcoin? - Git fkt.**  
**Signing Bitcoin in 1991.**  
**Y0UR H4RDW4R3 15 TH3 W4LL3T**

---

A minimal, paranoid, air-gapped / offline PSBT signer that runs on hardware from 1991 onward and fits on a real 1.44 MB floppy disk.

**Your hardware is the wallet.**  
The core is a completely offline signer that works anywhere you can run C — from a 486 with a floppy drive to a modern air-gapped machine.

### The Three Pieces (Current Scope)

**1. FKT CLI** — The core offline signer binary  
Pure C89 air-gapped PSBT signer. Runs on ancient hardware or any minimal environment. Stateless, RAM-only, produces signed PSBT + dense ASCII QR.

**2. FKT Bootable GUI** — The full bootable signer environment  
Minimal Linux GUI (Tiny Core based) that boots from USB/floppy and includes the CLI signer underneath. Designed as a practical daily-driver air-gapped device.

**3. FKT PWA** — The modern offline transaction coordinator  
Single-file offline HTML app. Drag & drop PSBTs, preview, edit, and either sign directly (WASM) or export to CLI for true air-gapped signing. Includes Paranoid Send Mode and educational debug view.

### Current Phase: v0.1.0 (CLI / DOS TUI)

**v0.1.0** ships the offline single-sig signer: BIP39 seed, P2WPKH + P2TR keypath, preview, dual CONFIRM, QR display — Linux CLI and DOS (`FKTSIGN.EXE`).

Not in 0.1: camera capture, Taproot script-path, Ark/Bark, multisig cosign productization, full PWA. See `cli/docs/RELEASE_v0.1.0.txt`.

### Philosophy

- Stateless by default — seed is never stored unless you explicitly choose encrypted backup.
- Maximum paranoia, minimum trust.
- Your old (or new) hardware is the wallet.
- Runs on hardware that existed before Bitcoin was even a concept.
- This is performance art as much as software.

### Key Generation & Backup

- On-device BIP39 generation with optional passphrase.
- Optional encrypted backup support (passphrase or Shamir’s Secret Sharing planned).

### Hardware Requirements

**Extreme retro path (CLI + Bootable GUI):**
- 486 computer + 3.5" 1.44 MB floppy drive (or USB boot)
- Blank floppies / USB stick

**Modern air-gapped path:**
- Any machine you can compile/run C on + browser for the PWA

### Current Status (July 2026)

- **v0.1.0**: offline PSBT signer — P2WPKH + P2TR keypath, TUI + CLI, DOS floppy build
- Release notes: `cli/docs/RELEASE_v0.1.0.txt`
- Post-0.1: script-path Taproot, Ark fixtures, multisig UX, camera, PWA
- Still air-gapped / test carefully; verify addresses on a second device

### Quick Start

```bash
git clone https://github.com/FloppyKit/fkt.git
cd fkt
make
```
(Build instructions will improve rapidly as we stabilize.)

License
MIT — see LICENSE

---
Coded Proudly in C89 - Bare fucking metal Bitcoin.


