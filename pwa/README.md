# FKT Offline PWA (ICED COLD)

**Functional Phase 0 (locked)** — single-file offline companion with real crypto.

- Unified camera QR scan (seed vs PSBT auto-detect) + BBQR / classic UR multi-frame
- BIP39 seed load / fingerprint / wipe-after-sign
- PSBT parse · human-first transaction review · Technical Details drawer
- Sign path (P2WPKH + P2TR keypath)
- KEYGEN entropy ritual (CLI-aligned)
- Green / amber CRT theme · offline pill
- Dense ASCII / download signed Base64 output

**No CDN. No simulate buttons. ALPHA / TESTNET experimental only.**

**Live (GitHub Pages):** [https://gitfkt.dev/pwa/](https://gitfkt.dev/pwa/)  
Landing: [https://gitfkt.dev/](https://gitfkt.dev/)

File: **`index.html`** (~360 KiB). Mirror: `fkt-offline.html`.

```bash
# camera often needs https or localhost:
cd pwa && python3 -m http.server 8765
# → http://127.0.0.1:8765/
```

Or open `index.html` from disk (camera may be blocked on `file://`).

Smoke: `python3 tests/run_pwa_smoke.py`  
Docs: `docs/releases/phase3-pwa.md`

**Phase 0 locked** after Small Polish (README honesty, size/dead-path audit, camera edge hardening, core-logic auditability comments). No further polish without explicit expand.
