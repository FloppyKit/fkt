# FKT Test Suite Roadmap

**Target**: ~95–110 total test vectors across V1–V4

This document tracks both **synthetic** and **real** test vectors for validating the FKT offline signer.

## Version Overview

| Version | Focus                              | Target Vectors | Synthetic | Real Vectors       | Status      | Priority |
|---------|------------------------------------|----------------|-----------|--------------------|-------------|----------|
| **V1**  | Core Single-Sig                    | 18–22          | Yes       | Sparrow            | In Progress | High     |
| **V2**  | Practical Multisig                 | 20–24          | Yes       | Sparrow            | Planned     | High     |
| **V3**  | Stretch + Ark Support              | 20–28          | Yes       | Sparrow + **Ark**  | Planned     | **High** |
| **V4**  | Polish, Robustness & Edge Cases    | 20–30          | Yes       | Sparrow + Ark      | Planned     | Medium   |

**Total Target**: **95–110 vectors**

---

## V1 – Core Single-Sig

**Script Types**:
- P2WPKH (various shapes: multi-input, RBF, locktime, dust, consolidation)
- P2TR Key-path
- P2SH-P2WPKH

**Current Status**: Synthetic suite complete (21 vectors). Moving to real Sparrow vectors.

---

## V2 – Practical Multisig

**Script Types**:
- P2WSH (primarily 2-of-2 and 2-of-3)
- P2SH-P2WSH (primarily 2-of-2 and 2-of-3)
- Mixed P2WPKH + P2WSH cases

**Status**: Planned after V1 real vectors are solid.

---

## V3 – Stretch Features + Ark Support (Gated)

**Gating Condition**: Taproot script-path signing must be stable before starting V3 work.

### Included in V3:
- Mixed input types (P2WPKH + P2TR, P2WPKH + P2WSH)
- Basic Taproot script-path (simple single-leaf cases)
- **Ark/Bark exit and boarding PSBTs** (Signet)

### Ark Scope (Locked)
- **Core CLI**: 
  - Proprietary key passthrough (including Ark’s custom keys)
  - Minimal input classification for preview context
  - Ability to sign the Taproot inputs used in Ark exits/claims
- **Higher layers** (PWA / GUI): Richer Ark metadata display (planned for later)
- No vUTXO logic or protocol state in FKT

**Ark Test Vectors**:
- Generated using the `bark` CLI on **Signet**
- Will include both boarding and unilateral exit PSBTs
- Some vectors will test graceful rejection of malformed Ark PSBTs

**Status**: Planned (after Taproot script-path is solid)

---

## V4 – Polish & Robustness

**Focus**:
- Complex/edge-case PSBTs
- Strong graceful rejection testing
- Final validation round of real Sparrow + Ark vectors
- Stress testing (high input/output counts, unusual combinations)

---

## Tracking & Status Definitions

| Status       | Meaning |
|--------------|---------|
| `TODO`       | Not yet created |
| `Synthetic`  | Generated and passing in synthetic suite |
| `Real`       | Validated against real Sparrow or Ark (Signet) vectors |
| `Verified`   | Signed PSBT produces correct on-chain result (especially important for Ark exits) |

**Target Mix**:
- ~70–75% "sign" cases
- ~25–30% graceful rejection / error cases

---

## Current Priorities (June 2026)

1. Finish modular refactor cleanup
2. Build synthetic test suite framework
3. Complete V1 real Sparrow vectors
4. Stabilize Taproot script-path signing
5. Begin V3 work (including first Ark Signet vectors)

---

**Last Updated**: 2026-06-09