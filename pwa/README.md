# FKT Offline PWA (Phase 3)

Single-file offline companion that **mirrors the DOS/Linux TUI**:

- **Main menu** on open (1–6, 0 exit)
- **Bottom status bar**: Seed / PSBT loaded (✅ / ⬜)
- **Load seed / Load PSBT**: camera **scan first**, button to switch to type/browse
- Preview · Sign (CONFIRM) · Show seed · Create wallet · signed Base64 + ASCII QR

File: **`index.html`** (~290 KiB, no CDN).

```bash
xdg-open index.html
# or (camera often needs https or localhost)
python3 -m http.server 8765
# → http://127.0.0.1:8765/
```

Smoke: `python3 tests/run_pwa_smoke.py`  
Docs: `docs/releases/phase3-pwa.md`
