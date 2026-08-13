# FKT PWA HUD / Discrete AR Output Layer — Sketch (2026-08-13)

**Status:** Planning intelligence only. No implementation yet.  
**Context:** Next-gen discrete AR / monocular green CRT-style HUDs (Halliday DigiWindow, Even Realities G1/G2, Brilliant Labs Frame, MentraOS, xg.glass, future retinal/contacts). Thin-client pattern dominates.  
**Goal:** Progressive enhancement of the existing offline PWA so the same logical green-CRT output can target phone DOM *or* a BLE/WebBT/WebView HUD sink without touching Ice Cold C89 or core crypto flow.

**Security posture (non-negotiable):**  
- Payloads are **display-only / public by design**.  
- Never carry seed, mnemonic, private keys, FROST shares, or signing material over BLE/WebBT.  
- FROST threshold + Ice Cold air-gap remain the secret boundary. PWA is the secure brain; HUD is just another output surface (status, preview lines, confirm prompts, QR handoff data).  
- Feature-detect + graceful fallback to current DOM CRT. Air-gap path completely untouched.

## Why this fits FKT

- PWA already has the green-on-black CRT aesthetic and TUI-shaped flow (menu, pinned status, preview, sign confirm, dense QR).  
- ROADMAP Phase 4 (Mock Nostr + harness) is the current product work; this is a parallel planning reservation so we do not paint ourselves into a mobile-only corner.  
- Dominant industry pattern: glasses/projector = thin client (display + low-power I/O); companion (phone/PWA) = brain. Perfect match for our architecture.

## Minimal Logical Payload (versioned, low-bandwidth)

```json
{
  "v": 1,
  "type": "status" | "preview" | "prompt" | "qr" | "lines" | "clear",
  "session": "short-id",
  "ts": 0,
  "content": [
    { "t": "text or vector description", "s": "dim|hi|alert|vector", "y": optional }
  ],
  "meta": {
    "psbt_fp_short": "optional short fingerprint",
    "state": "loaded|preview|confirm|signed|error"
  }
}
```

- `content` is an array of simple lines or vector primitives suitable for monochrome green micro-displays.  
- QR type carries only the already-public dense ASCII / BBQR / UR data the PWA already generates for handoff.  
- No secrets. Ever.

## Sinks (progressive detection order)

1. **Default** — existing DOM CRT renderer (current single-file offline behaviour).  
2. **Web Bluetooth** — Brilliant Labs Frame/Halo style or community reverse-eng for Even/Halliday-class devices (Chromium; not iOS).  
3. **Even Hub / WebView bridge** — Even Realities official path (web apps inside companion).  
4. **xg.glass / MentraOS adapters** — unified thin APIs (`displayText` / `displayImage` style) when available.  
5. **External display / retinal** — USB-C DP Alt Mode (QD Laser VIEWCLEAR class) treated as another screen sink.  
6. **WebXR inline** (optional later) — for spatial if ever needed; not required for monocular HUD.

## Integration points in current PWA

- After every status/footer update.  
- After preview render.  
- On sign-confirm prompt.  
- On QR / Base64 generation.  
- On clear / wipe / exit.

Emit the same logical payload to all active sinks. Keep the single-file offline purity; any adapter is feature-flagged / optional and must degrade cleanly when the transport is absent.

## C89 / Ice Cold boundary

Unchanged. Any future device-side driver or protocol stub stays a pure thin output module (analogous to the existing dense ASCII QR surface). Signer core never learns about HUDs.

## Next actions (non-blocking)

- Reserve this contract while Phase 4 Mock Nostr proceeds.  
- When a concrete device (Even G1/G2, Brilliant, or Mentra Live) is in hand, implement one sink as proof.  
- Document any BLE UUID / command mapping discovered in a follow-up plan under `docs/plans/`.

**Retrievable via:** `docs/plans/2026-08-13-pwa-hud-output-layer.md` on `main`.  
**Handoff tag context:** continues from `handoff-v0.3.0-multisig` / Phase 4 work.
