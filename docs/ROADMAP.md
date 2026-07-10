# FKT Master Roadmap — Checkpoint

**Handoff tag (give this back to the agent):** `handoff-v0.3.0-multisig`  
**Also:** release tag **`v0.3.0`** (same commit)  
**Date:** 2026-07-10  
**Principle:** Signing perfect first. Ice Cold never gains seed-file code. Warm never merges into `main`.

---

## Where we are (this tag)

| Track | Status | Git |
|-------|--------|-----|
| **Phase 1 — Ice Cold CLI** | **DONE** | `main` · tag **`iced-cold-v1`** (product was **0.2.1**) |
| **V2 multisig (native P2WSH)** | **DONE (synthetic)** | `main` · tags **`v0.3.0`** + **`handoff-v0.3.0-multisig`** · product **`0.3.0`** |
| **Phase 2 — Warm wallet** | **DONE** (isolated) | branch **`warm-wallet`** · tag **`warm-v1`** |
| **Phase 3 — Offline PWA** | **DONE** (v1 shell) | `main` · tag **`phase3-pwa-v1`** |
| **Phase 4 — Mock Nostr + harness** | **NOT STARTED** | default next product phase |
| **Phase 5 — SDKs + coordinator → v1.0** | **NOT STARTED** | after Phase 4 |

### Packaging (canonical — do not confuse)

| Medium | Build | Artifact |
|--------|-------|----------|
| **1.44 MB floppy** | DOS `Makefile.dos` | `FKTSIGN.EXE` + `CWSDPMI` → `dist/floppy-iced-cold/` |
| **Bootable USB / GUI** | Linux `Makefile` | `fktsigner` inside tiny secure live Linux |
| **Browser companion** | static | `pwa/index.html` single-file offline (~290 KiB) |

### Key tags

| Tag | Meaning |
|-----|---------|
| `iced-cold-v1` | Ice Cold CLI + DOS floppy, product **0.2.1** |
| `warm-v1` | Encrypted seed file — **only** on `warm-wallet` |
| `phase3-pwa-v1` | First single-file PWA |
| `handoff-phase3-complete` | Older checkpoint (pre-multisig) |
| **`v0.3.0`** | Native P2WSH multisig cosign + finalize |
| **`handoff-v0.3.0-multisig`** | **This checkpoint** — resume here |

### Verify quickly

```bash
git fetch --tags origin
git checkout handoff-v0.3.0-multisig   # or main after pull

cd cli && make && make test            # includes test-multisig
make test-multisig                     # V2 multi only
./scripts/stage_floppy.sh && ./scripts/dosbox_smoke.sh   # if DOS tree present

git checkout warm-wallet && cd cli && make warm && make test-warm

git checkout main   # or handoff tag
python3 pwa/tests/run_pwa_smoke.py
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
7. Taproot **script-path** single-leaf + ark-shaped CSV/CLTV leaves (`make test-scriptpath` / `test-scriptpath-ark`)

### V2 multisig — native P2WSH (v0.3.0)

8. Cosign: BIP143 + DER → `PARTIAL_SIG` when key is in witness script  
9. Multi-deriv match: walk all `PSBT_IN_BIP32_DERIVATION` on an input  
10. Finalize when ≥ *m* partials: witness `[OP_0][sigs…][witnessScript]`  
11. Parse accepts `PARTIAL_SIG` (second cosigner round-trip)  
12. Preview shows `m-of-n cosign`; status `[PARTIAL]` / `[FINALIZED]`  
13. Auto: `make test-multisig` (1of1 / 2of2 / 2of3 / wrong seed)  
14. Product string **`0.3.0`**

### Phase 2 — Warm (branch only)

15. AES-256-GCM seed file + PBKDF2 — tag **`warm-v1`** on **`warm-wallet`** only  

### Phase 3 — Offline PWA

16. Single-file offline companion + TUI shell (menu, footer, scan-first)  

---

## Remaining plan (next work)

### Human parallel (non-blocking) — good next if user wants signing polish

| Item | Owner | Done when |
|------|-------|-----------|
| Sparrow multi vectors S1/S2/S4 | Human | Files in `cli/tests/sparrow-real/unsigned/` per `docs/plans/2026-07-10-v2-multisig-sparrow-manual.md` |
| Wire Sparrow multi into harness | Agent | Manifest rows + `make test-sparrow-real` green |
| Live bark exit-claim capture | Human + agent | Unsigned claim PSBT + FKT sign |
| Matt DOS hardware TUI smoke | Human | `cli/docs/DOS_TEST_STATUS.txt` |

### Phase 4 — Mock Nostr relay + harness  **← product phase next (unless user redirects)**

| # | Work | Done when |
|---|------|-----------|
| 4.1 | Local **mock Nostr relay** (test server) | Runs offline; docs how to start |
| 4.2 | Message shapes (NIP-44/46 as applicable) | Spec + fixtures in repo |
| 4.3 | Support surfaces in mock (stubs OK): LN + Cashu (NWC), on-chain (Floresta), Silent Payments, **Ark** | Green or explicit SKIP |
| 4.4 | PWA online flow tests against mock | `make test-pwa-coord` or similar |
| 4.5 | Keep Ice Cold offline path untouched | No seed-file / no relay in DOS binary |

**Out of scope for FKT CLI itself:** holding ASP keys, MuSig rounds inside Ice Cold, full node.

### Phase 5 — SDKs + coordinator → ship v1.0

| # | Work | Done when |
|---|------|-----------|
| 5.1 | Extract **C lib** wrapper (Ice Cold signing path) | Header + static lib + example |
| 5.2 | Extract **JS SDK** from PWA crypto surface | Single-file OK |
| 5.3–5.6 | Coordinator API + integrations → tag **`v1.0`** | Announce-ready |

### Explicit non-goals until later

- Merging Warm into `main`  
- Full BIP174 unknown-key pass-through (non-`0xFC` still hard-abort by design)  
- Nested P2SH-P2WSH multi (stretch only)  
- MuSig2 / pool / ASP protocol inside FKT  
- Mainnet “production ready” claims  

---

## Agent resume instructions

When the user says: **“continue from `handoff-v0.3.0-multisig`”** (or hands you that tag):

1. `git fetch --tags && git checkout handoff-v0.3.0-multisig` (or `main` if equal)  
2. Read **this file** (`docs/ROADMAP.md`)  
3. Confirm: `cd cli && make test-multisig` (must PASS)  
4. Default product work: **Phase 4.1** (mock Nostr) **unless** user asks for Sparrow multi vectors, live bark exit-claim, or DOS  
5. Do **not** put Warm seed-file code on `main`  
6. Keep interfaces text-consistent across DOS / Linux / PWA  
7. Product version is **`0.3.0`** (`cli/fkt_version.h`)

### Session context (why we stopped here)

- V2 native P2WSH multisig cosign + finalize landed and auto-tested.  
- User still has **optional** Sparrow manual vectors to export (S1/S2/S4).  
- Ark/Bark: synthetic script-path leaves + 0xFC done; **live** exit-claim still human when funds exist.  
- Next major product track after human polish: **Phase 4 mock Nostr**.

---

## Related docs

- Multisig release: `docs/releases/v0.3.0-multisig.md`  
- Sparrow multi how-to: `docs/plans/2026-07-10-v2-multisig-sparrow-manual.md`  
- Ark-shaped leaves: `docs/plans/2026-07-09-ark-shaped-scriptpath-leaves.md`  
- Signing path plan: `docs/plans/2026-07-09-next-steps-signing-path.md`  
- Ice Cold: `docs/releases/iced-cold-v1.md`  
- Warm: `docs/releases/warm-v1.md` (on `warm-wallet`)  
- PWA: `docs/releases/phase3-pwa.md`  
- Module map: `cli/docs/MODULE_MAP.md`  
- Test vectors: `cli/tests/TEST_VECTORS.md`  
- Test seeds: `cli/tests/TEST_SEEDS.md`  
