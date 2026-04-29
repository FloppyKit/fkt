# FKT — Floppy Kit

**Will it bitcoin?**  
**Git fkt.**  
**Signing Bitcoin in 1991.**  
**Y0UR H4RDW4R3 15 TH3 W4LL3T**

---

A minimal, paranoid, air-gapped PSBT signer that runs on hardware from 1991 onward and fits on a real 1.44 MB floppy disk.

Your hardware is the wallet.

### The Three Pieces

**FKT CLI**  
The pure air-gapped signer.  
- Runs on a 486 (or older) from a floppy disk.  
- Completely stateless, RAM-only, no network.  
- Seed phrase entry with verification (four modes).  
- Full signing support: P2WPKH, P2WSH multisig, Taproot.  
- Outputs signed PSBT + dense scannable ASCII QR.  

**FKT PWA**  
The modern transaction coordinator and daily driver.  
- Single-file offline HTML, runs in any browser.  
- Drag & drop or paste PSBT.  
- Clean transaction preview.  
- **Paranoid Send Mode** (wallet sweep, automatic change splitting, optional noise output).  
- Sign directly in the PWA (WASM) or export to CLI.  
- QR scanning and ASCII QR output.  
- Toggleable **Debug / Educational Mode** — shows step-by-step explanations of every part of the signing process.  

**Uncle Jim’s Relay**  
The optional community data & broadcast layer.  
- Provides fresh fee estimates and recent chain data to the PWA.  
- Stores the last 180 days of transaction history (configurable).  
- Receives signed transactions and automatically broadcasts them.  
- Runs as a Tor-only onion service with no connection logging and dummy traffic for extra privacy.  
- Toggle between public APIs (default) and your own local pruned node (Floresta recommended).  

### Hardware Requirements

**FKT CLI (Signer)**  
- 486 computer  
- 3.5" 1.44 MB floppy drive (5.25" optional for extra flex)  
- Blank floppies  

**Uncle Jim’s Relay (Community Server)**  
**Recommended:**  
- Pentium III (800 MHz – 1.4 GHz)  
- 512 MB – 1 GB RAM  
- 32 GB hard drive  
- Zip drive + at least one 100 MB Zip disk (for installation)  

**Minimum:**  
- Pentium II, 256 MB RAM, 8–16 GB drive (slower but works)

### Scaling

A single well-specced Pentium III can comfortably serve hundreds of users.  
At very large scale (tens or hundreds of thousands of users), a few modern mini PCs or a small server is sufficient.

### Philosophy

- Stateless by default — seed is never stored unless you explicitly choose an encrypted backup (v2.0).  
- Maximum paranoia, minimum trust.  
- Your old junk is the wallet.  
- Runs on hardware that existed before Bitcoin was even a concept.  
- This is performance art as much as software.

**Key Generation & Backup (v2.0)**  
On-device BIP39 generation with optional passphrase.  
Optional encrypted backup (passphrase or Shamir’s Secret Sharing).

### License

GPL-3.0 — see [LICENSE](LICENSE)

---
Coded Proudly in C89 - Bare fucking metal Bitcoin.

-  Uncle Jim.
