# FKT — Floppy Kit

<table>
<tr>
<td width="60%">


# **Will it Bitcoin?  –  Git FKT**  
 **Signing Bitcoin in 1991.**  
 
 **Y0UR H4RDW4R3 15 TH3 W4LL3T**


</td>
<td width="40%">
<img width="360" height="480" alt="fktlogo" src="https://github.com/user-attachments/assets/2c5baf87-cf6f-4f9d-afcc-882a3fc40f20" />
</td>
</tr>
</table>


A minimal, paranoid, air-gapped Bitcoin PSBT signer that runs on hardware from 1991 onward and fits on a real 1.44 MB floppy.



> **⚠️ ALPHA / TESTNET & EXPERIMENTAL USE ONLY**  
> Do **not** use with real funds.  
> This is still early, actively changing code. Expect breaking changes and rough edges.  
> Feedback, test vectors, and brutal review are welcome.

---

### Philosophy

- Stateless by default (Ice Cold builds never persist seed material)
- Maximum paranoia, minimum trust, minimum code
- Strict ANSI C89 + static `libsecp256k1` only
- Runs on machines that existed before Bitcoin was a concept
- This is performance art as much as software

### Current Status (July 2026)

| Component              | Status                          | Notes |
|------------------------|----------------------------------|-------|
| **CLI (Ice Cold)**     | Solid / usable                  | P2WPKH + Taproot keypath, real Sparrow vectors, dense ASCII QR |
| **DOS / Floppy**       | Working (`FKTSIGN.EXE`)         | Ready for 486-class hardware validation |
| **PWA**                | Rough single-file sketch        | State-based dashboard exists, not yet daily-driver polished |
| **Warm (encrypted seed)** | Designed, not fully polished | Optional encrypted backup path with loud warnings |
| **Ark / BARC / OpenARC** | Explicitly later (V3)         | Not in current scope |
| **USB GUI (FKT-144)**  | Planned                        | Bootable Tiny Core path |

The core signing path is real. The rest is still under construction.

### The Three Pieces

1. **FKT CLI** — Pure C89 offline signer. Stateless, RAM-only, produces signed PSBT + dense ASCII QR.  
   Packaging: `FKTSIGN.EXE` (DOS / 1.44 MB floppy) and Linux binary.

2. **FKT Bootable GUI (FKT-144)** — Minimal live Linux environment (~100–144 MB target) that wraps the same signer with camera + state-based UI.

3. **FKT PWA** — Single-file offline web companion for PSBT creation, preview, and QR handoff to the air-gapped tools.

### Ice Cold vs Warm

- **Ice Cold** (recommended for real keys): Every seed-persistence path is *deleted* from the binary. Paranoid users can verify with `strings` / disassembly.
- **Warm**: Optional encrypted seed file support (age-style) + mandatory loud warnings. Intended for ritual / performance / controlled educational machines only. Core preview-before-seed discipline is preserved.

### Quick Start (Linux)

```bash
git clone https://github.com/FloppyKit/fkt.git
cd fkt/cli
make
./fktsigner --help
```


DOS / floppy build instructions live in cli/docs/ and dist/floppy-iced-cold/.
Hardware Notes

Extreme retro path: 486 (or equivalent) + 3.5" 1.44 MB floppy drive

Modern air-gapped path: any machine that can run the C binary + a second device for QR / file handoff

486 validation Txid: 92fc1a0e1d4d54d4b1e9cda801f0f4065a75be38fd6752385957167ca7de54c7

Security Model (short version)

Seed material exists in RAM only for the duration of a signing session (Ice Cold)
Hard abort on any malformed PSBT, unknown keys, negative fees, unsupported scripts, etc.
All sensitive memory is zeroed with volatile loops
Preview + confirmation before any private key material is derived

Credits
Floppy Kit is a collaboration between human and machine.
The current iteration has significant code contributions by Deepseek and Grok
Grok is as a core member of the Floppy Kit team.
License
MIT — see LICENSE

***Coded proudly in C89***

***Bare Metal Bitcoin***
