# FKT Offline PWA (ICED COLD)

**Status: Functional Phase 0 (locked)**

Single-file offline companion — real crypto, CRT dashboard, no CDN:

- Unified camera QR (seed / PSBT + BBQR / UR multi-frame)
- BIP39 seed load / fingerprint / wipe-after-sign
- PSBT parse · human-first review · Technical Details
- Sign path: P2WPKH + P2TR keypath (no CONFIRM typing gate)
- KEYGEN entropy ritual (CLI-aligned)
- Green / amber CRT theme · offline-only (no manifest / service worker)

**ALPHA / TESTNET only.** No classic install surface.

**Live (GitHub Pages):** [https://gitfkt.dev/pwa/](https://gitfkt.dev/pwa/)  
Landing: [https://gitfkt.dev/](https://gitfkt.dev/)

File: **`index.html`** (~355 KiB). Mirror: `fkt-offline.html` (same bytes).

```bash
# camera often needs https or localhost:
cd pwa && python3 -m http.server 8765
# → http://127.0.0.1:8765/
```

Or open `index.html` from disk (camera may be blocked on `file://`).

Smoke: `python3 tests/run_pwa_smoke.py`  
Docs: `docs/releases/phase3-pwa.md`

**Phase 0 locked** after Small Polish (README honesty, size/dead-path audit, camera edge hardening, core-logic auditability comments). No further polish without explicit expand.
