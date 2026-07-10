# FKT Master Roadmap — Checkpoint

**Handoff tag (give this back to the agent):** `handoff-phase3-complete`  
**Date:** 2026-07-09  
**Principle:** Signing perfect first. Ice Cold never gains seed-file code. Warm never merges into `main`.

---

## Where we are (this tag)

| Track | Status | Git |
|-------|--------|-----|
| **Phase 1 — Ice Cold CLI** | **DONE** | `main` · tag **`iced-cold-v1`** · product string **`0.2.1`** |
| **Phase 2 — Warm wallet** | **DONE** (isolated) | branch **`warm-wallet`** · tag **`warm-v1`** |
| **Phase 3 — Offline PWA** | **DONE** (v1 shell) | `main` · tag **`phase3-pwa-v1`** + TUI shell at this handoff |
| **Phase 4 — Mock Nostr + harness** | **NOT STARTED** | next product phase |
| **Phase 5 — SDKs + coordinator → v1.0** | **NOT STARTED** | after Phase 4 |

### Packaging (canonical — do not confuse)

| Medium | Build | Artifact |
|--------|-------|----------|
| **1.44 MB floppy** | DOS `Makefile.dos` | `FKTSIGN.EXE` + `CWSDPMI` → `dist/floppy-iced-cold/` |
| **Bootable USB / GUI** | Linux `Makefile` | `fktsigner` inside tiny secure live Linux |
| **Browser companion** | static | `pwa/index.html` single-file offline (~290 KiB) |

### Key tags already on origin

| Tag | Meaning |
|-----|---------|
| `iced-cold-v1` | Stateless Ice Cold CLI + DOS floppy package, version **0.2.1** |
| `warm-v1` | Encrypted seed file (AES-GCM) — **only** on `warm-wallet` |
| `phase1-step-2-psbt-core` … `phase1-step-5-retro` | Intermediate Phase 1 gates |
| `phase3-pwa-v1` | First single-file PWA |
| **`handoff-phase3-complete`** | **This checkpoint** (roadmap + PWA TUI shell) |

### Verify quickly

```bash
git fetch --tags origin
git checkout handoff-phase3-complete   # or main after pull

cd cli && make && make test            # Ice Cold suite
./scripts/stage_floppy.sh && ./scripts/dosbox_smoke.sh

git checkout warm-wallet && cd cli && make warm && make test-warm

git checkout main
python3 pwa/tests/run_pwa_smoke.py
# UI: cd pwa && python3 -m http.server 8765
```

---

## Done detail (do not re-litigate)

### Phase 1 — Ice Cold CLI (stateless)

1. Proprietary BIP174 `0xFC` passthrough (global/input/output)  
2. Modular PSBT core (P2WPKH + Taproot keypath + 0xFC)  
3. CLI entry: preview → seed → sign → binary + Base64 + optional QR  
4. Full suite: BIP vectors, Sparrow matrix, multi-input, SP **stub**  
5. DOS retro build + size audit (~21% of 1.44 MB) + DOSBox smoke  
6. Tag **`iced-cold-v1`** (banner/version **0.2.1**)  

### Phase 2 — Warm (branch only)

7. AES-256-GCM seed file + PBKDF2; `save-seed` / `--seed-file` / `set-autoload`  
8. Tag **`warm-v1`** on **`warm-wallet`** — **never merge into main**  

### Phase 3 — Offline PWA

9. Single-file offline green-on-black companion (drag/drop, seed, sign, QR)  
10. TUI-shaped shell: **main menu**, **bottom Seed|PSBT status**, **scan-first** load + type/browse fallback  
11. Smoke: `python3 pwa/tests/run_pwa_smoke.py`  

---

## Remaining plan (next work)

### Phase 4 — Mock Nostr relay + harness  **← START HERE next session**

| # | Work | Done when |
|---|------|-----------|
| 4.1 | Local **mock Nostr relay** (test server) for coordination / round messages | Runs offline; docs how to start |
| 4.2 | Message shapes aligned with PsychArts-Retroverse / relayspec (NIP-44/46 as applicable) | Spec + fixtures in repo |
| 4.3 | Support surfaces in mock (stubs OK): **LN + Cashu (NWC)**, **on-chain (Floresta pruned)**, **Silent Payments** signing path, **Ark** (lean OpenArk/Bark) | Harness cases green or explicit SKIP with reason |
| 4.4 | PWA **online flow tests** against mock (not mainnet) | `make test-pwa-coord` or similar |
| 4.5 | Keep Ice Cold offline path untouched | No seed-file / no relay in DOS binary |

**Out of scope for FKT CLI itself:** holding ASP keys, MuSig rounds inside Ice Cold, full node.

### Phase 5 — SDKs + coordinator → ship v1.0

| # | Work | Done when |
|---|------|-----------|
| 5.1 | Extract **C lib** wrapper (Ice Cold signing path) | Header + static lib + tiny example |
| 5.2 | Extract **JS SDK** from PWA crypto surface | npm-less or vendored single file OK |
| 5.3 | First SDK release **without** full coordinator | Tags / docs |
| 5.4 | PWA **coordinator API** (mock first, then real Nostr relay) | Endpoints documented |
| 5.5 | Wire LN/Cashu/NWC, Floresta, Silent Payments, Ark via coordinator | Integration tests against mock |
| 5.6 | Final ship: PWA + SDKs + online coordinator support | Tag **`v1.0`**, update docs/manifest/releases/floppy notes, announce-ready |

### Parallel / non-blocking

| Item | Owner | Notes |
|------|-------|-------|
| Matt DOS hardware TUI smoke | Human | `cli/docs/DOS_TEST_STATUS.txt` |
| Linux USB live image packaging | Later | Uses Linux `fktsigner`, not floppy size budget |
| Live bark exit-claim vector | When funds/export exist | Signing path polish |
| PWA camera/jsQR polish | As needed | Scan-first already default |

### Explicit non-goals until later

- Merging Warm into `main`  
- Full BIP174 unknown-key pass-through (non-`0xFC` still hard-abort by design)  
- Mainnet “production ready” claims  
- MuSig2 / pool / ASP protocol inside FKT  

---

## Agent resume instructions

When the user says: **“continue from `handoff-phase3-complete`”**:

1. `git fetch --tags && git checkout handoff-phase3-complete` (or `main` if equal)  
2. Read **this file** (`docs/ROADMAP.md`)  
3. Start **Phase 4.1** (mock Nostr relay) unless user redirects  
4. Do **not** put Warm seed-file code on `main`  
5. Keep interfaces text-consistent across DOS / Linux / PWA  

---

## Related docs

- Signing path detail: `docs/plans/2026-07-09-next-steps-signing-path.md`  
- Ice Cold release: `docs/releases/iced-cold-v1.md`  
- Warm release: `docs/releases/warm-v1.md` (on `warm-wallet` branch)  
- PWA release: `docs/releases/phase3-pwa.md`  
- Module map: `cli/docs/MODULE_MAP.md`  
- Test vectors: `cli/tests/TEST_VECTORS.md`  
