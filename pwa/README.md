# FKT Offline PWA (ICED COLD)

Single-file offline companion — **Phase 0 dashboard shell** with real crypto:

- Unified camera QR scan (seed vs PSBT auto-detect)
- BIP39 seed load / fingerprint / wipe
- PSBT parse · human-first transaction review · Technical Details
- Sign path (P2WPKH + P2TR keypath) — no CONFIRM typing gate
- KEYGEN entropy ritual (CLI-aligned)
- Green / amber CRT theme · offline pill
- Dense ASCII / download signed Base64 output

**No CDN. No simulate buttons. ALPHA / TESTNET experimental.**

**Live (GitHub Pages):** [https://gitfkt.dev/pwa/](https://gitfkt.dev/pwa/)  
Landing: [https://gitfkt.dev/](https://gitfkt.dev/)


File: **`index.html`** (~320 KiB). Mirror: `fkt-offline.html`.

```bash
# camera often needs https or localhost:
cd pwa && python3 -m http.server 8765
# → http://127.0.0.1:8765/
```

Or open `index.html` from disk (camera may be blocked on `file://`).

Smoke: `python3 tests/run_pwa_smoke.py`  
Docs: `docs/releases/phase3-pwa.md`
