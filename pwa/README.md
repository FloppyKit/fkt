# FKT Offline PWA (Phase 3)

Single-file offline PSBT companion: **`index.html`** (~140 KiB).

```bash
xdg-open index.html
# or
python3 -m http.server 8765
```

See `docs/releases/phase3-pwa.md`. Smoke: `python3 tests/run_pwa_smoke.py`.

Do not load over the public internet if you care about supply-chain; keep a local copy.
