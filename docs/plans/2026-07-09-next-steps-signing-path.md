# Plan: Next steps on the signing path (post v0.2.0)

**Date:** 2026-07-09  
**Branch:** `main`  
**Canonical full roadmap:** [`docs/ROADMAP.md`](../ROADMAP.md)  
**Handoff tag:** `handoff-phase3-complete` (Phases 1–3 done; Phase 4 next)  
**Tags in force:** `iced-cold-v1` (product 0.2.1), `warm-v1` (branch only), `phase3-pwa-v1`, plus intermediate `phase1-step-*`  
**Principle:** Signing perfect first. Ice Cold bar is green; coordinator/relay is next (Phase 4).

### Packaging (canonical)

| Medium | Build | Binary | Notes |
|--------|-------|--------|-------|
| **1.44 MB floppy** | DOS (`Makefile.dos`) | `FKTSIGN.EXE` + `CWSDPMI.EXE` | Primary retro deliverable; size audit applies |
| **Bootable USB / GUI** | Linux (`Makefile`) | `fktsigner` in tiny secure live Linux | Same crypto path; host basis for GUI stack |

Warm seed-file work stays on an isolated branch later. Never merge into Ice Cold main.

---

## 0. Where we are (done)

| Milestone | Evidence |
|-----------|----------|
| Sparrow real matrix layout + harness + goldens | `make test-sparrow-real` / `test-sparrow-real-golden` |
| True mixed P2WPKH + P2TR inputs | Merged legs; FKT signs both |
| Full Linux CLI + TUI + DOS build tree on `main` | `make`, `make -f Makefile.dos` |
| Linux CLI/TUI crypto parity | `make test-parity-linux` → PASS=15 |
| Synthetic single-leaf script-path | `make test-scriptpath` |
| Proprietary 0xFC passthrough (global/input/output) | `v0.2.2` / `make test-proprietary` |
| Modular PSBT core map + zero-warning Ice Cold build gate | `cli/docs/MODULE_MAP.md` / `make test-psbt-core` |
| CLI entry: preview→seed→sign, binary+Base64, 3-word verify, QR | `make test-cli-entry` |
| Full suite: BIP vectors + Sparrow/Bark 0xFC + multi-in + SP stub | `make test` |
| Retro DOS + floppy size audit (~21% of 1.44 MB) | `make test-retro` / `scripts/stage_floppy.sh` |
| Ice Cold v1 ship tag (product string `0.2.1`) | tag `iced-cold-v1` |
| Warm encrypted seed (isolated branch) | branch `warm-wallet` / tag `warm-v1` — never merge to main |
| Offline PWA (TUI-shaped shell, scan-first load) | `pwa/index.html` / `phase3-pwa-v1` + handoff tip |
| GitHub hygiene | `main` + `warm-wallet` only for product tracks |

**Next:** Phase 4 mock Nostr relay — see `docs/ROADMAP.md`.  

**Deferred (human):** DOS hardware TUI smoke (`cli/docs/DOS_TEST_STATUS.txt`).  
**Blocked externally:** Second signet faucet bech32m — **do not block crypto packages.**

---

## 1. North star (what “done enough” means for FKT CLI)

FKT remains a **single BIP39 offline PSBT signer** (Ice Cold / Warm). Success for this path:

1. **Keypath** single-sig (P2WPKH, P2TR, nested, mixed) — **done**  
2. **Script-path** single-sig leaves with control block — **synthetic done**; real/bark-shaped next  
3. **Ark offline value:** sign **user-key exit-claim** PSBTs (and optional board/CPFP if exported as normal PSBTs)  
4. **Not** MuSig rounds, ASP protocol, LN, Arkoor, or CTV inside FKT  

Version bumps when the support bar is met (not by calendar).

---

## 2. Ordered work packages

### P0 — Stabilize what we shipped (short)

| # | Package | Owner | Done when |
|---|---------|-------|-----------|
| P0.1 | Matt: DOS runtime smoke (`FKTSIGN.EXE sign … --yes`) on 2–3 vectors | Matt | Notes in `cli/docs/DOS_TEST_STATUS.txt` or issue |
| P0.2 | Optional: CI job on `main` for `make` + `test-parity-linux` + `test-scriptpath` (no DOSBox) | agent | Green CI on push |
| P0.3 | Golden refresh after any intentional signer change | agent | `test-sparrow-real-golden` still green |

**Priority:** P0.1 is human-only; P0.2/P0.3 can wait if we push signing crypto.

---

### P1 — Script-path hardening toward Ark leaves (**next agent package**)

Goal: prove script-path is not only “one synthetic CHECKSIG” but **timelock-shaped user leaves** without live bark.

| # | Package | Type | Done when |
|---|---------|------|-----------|
| P1.1 | Spec bark-like leaf templates (DelayedSign / TimelockSign / DelayedTimelockSign **shapes only** — not full bark consensus) | docs | **Done** — `docs/plans/2026-07-09-ark-shaped-scriptpath-leaves.md` |
| P1.2 | Synthetic generators: leaf with `OP_CHECKSIG` + CSV and/or CLTV prefixes; valid control block + merkle root | tooling | **Done** — `make gen-scriptpath-fixtures` / `test-scriptpath-ark` |
| P1.3 | Harness cases `expect=sign` for those fixtures; reject cases (tree, no leaf; wrong seed) | test | **Done** — harness PASS includes csv/cltv/csv_cltv + reject_noleaf |
| P1.4 | Tag **`v0.2.1`** if only fixtures; **`v0.3.0`** if we also land proprietary passthrough (see P2) | release | **v0.2.1** tagged after P1 |

**Why before faucet:** offline correctness of sighash + witness stack is the real gate for exit claims.

---

### P2 — PSBT product gaps for “real world offline”

| # | Package | Type | Done when |
|---|---------|------|-----------|
| P2.1 | **Proprietary key passthrough** — do not strip unknown/bark `0xFC` keys on sign | code | **Done** — v0.2.2; harness `p2wpkh_proprietary_passthrough` |
| P2.2 | Nested P2SH-P2WPKH: decide finalize vs partial_sig-only for product TUI message | product | Documented + test |
| P2.3 | P2WSH: partial_sig only, clear “not fully supported” | product | Reject/partial fixtures documented |
| P2.4 | ANYONECANPAY / non-default sighash: explicit support or clean reject | code+test | Manifest `expect` matches behavior |

---

### P3 — Live Ark path (when funds exist)

| # | Package | Owner | Done when |
|---|---------|-------|-----------|
| P3.1 | Signet L1 coins via **tb1q** faucet → send into bark (bypass broken `tb1p` faucet UI) | Matt | Funded bark wallet |
| P3.2 | Capture **unsigned exit-claim** (or reconstruct) with known mnemonic | hybrid | File under `cli/tests/sparrow-real/unsigned/` or `ark/` |
| P3.3 | FKT sign offline → broadcast claim | hybrid | On-chain confirm or documented fail with PSBT preserved |
| P3.4 | Optional board funding: only if bark/BDK can dump unsigned PSBT with paths | later | Documented; else “bark-internal” |

**Success tag:** e.g. `v0.3.0` = script-path + passthrough + at least one live or high-fidelity synthetic exit claim.

---

### P4 — Test matrix breadth (V2 / V4 in ROADMAP terms)

Do **not** block P1–P3 on full 100 vectors.

| # | Package | Done when |
|---|---------|-----------|
| P4.1 | Multisig real fixtures (2-of-2 / 2-of-3) with known test seeds | partial_sig cases automated |
| P4.2 | Reject corpus expansion (malformed, duplicate outpoint, already-finalized) | harness covers expect=reject |
| P4.3 | Reconcile synthetic suite + sparrow-real under one `make test` umbrella | One green command for “signer OK” |

---

### P5 — Explicitly parked (until signing bar for Ark offline is met)

- PWA features, Nostr relay product work  
- Camera, full USB GUI polish beyond what signs  
- MuSig2 / pool / refresh inside FKT  
- Mainnet anything  

Redirect: *“Signing perfect first — we can park that.”*

---

## 3. Suggested execution order (next 2–4 agent sessions)

```text
Session A:           P1.1 + P1.2 + P1.3   bark-shaped synthetic leaves  (done, v0.2.1)
Session B:           P2.1                 proprietary passthrough      (done, v0.2.2)
Session C:           P0.2 CI (optional) + polish / P2.2–P2.4 product gaps
Session D (human):   P0.1 DOS smoke + P3.1 faucet workaround
Session E:           P3.2–P3.3 live claim when funded
```

---

## 4. Definition of “Ark-ready offline signer”

Checklist:

- [x] Keypath matrix green (Linux)  
- [x] Script-path single-leaf synthetic green  
- [x] Script-path CSV/CLTV-shaped leaves green  
- [x] Proprietary keys survive sign  
- [ ] At least one bark-shaped or live exit-claim vector signed  
- [ ] Matt DOS smoke (nice-to-have, not gate)  
- [ ] Faucet optional — synthetic can satisfy “crypto ready” without live Ark  

---

## 5. Cold start

```bash
git fetch --tags origin && git checkout main && git pull
# this plan:
#   docs/plans/2026-07-09-next-steps-signing-path.md
# prior:
#   docs/plans/2026-07-09-v0.2-script-path.md
#   docs/plans/2026-07-09-post-v0.1-sparrow-and-ark-offline.md
#   docs/releases/v0.1.1.md  v0.2.0.md
cd cli && make && make test-parity-linux && make test-scriptpath
```

---

## 6. Immediate recommendation

**Session B done (P2.1).** Next agent leverage: P2.2–P2.4 product gaps, optional CI (P0.2),  
or wait on live Ark (P3) when funded. DOS smoke remains human-only (P0.1).
