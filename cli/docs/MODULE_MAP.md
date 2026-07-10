FKT CLI — Modular PSBT / crypto map (Ice Cold)
==============================================
Phase 1 Step 2. Signing perfect first. No single mega-file.

Packaging targets (do not confuse)
----------------------------------
  DOS  (Makefile.dos → FKTSIGN.EXE)
    Primary form factor for the classic 1.44 MB floppy image.
    Retro CRT/LCD, FreeDOS / MS-DOS, DJGPP + CWSDPMI.

  Linux (Makefile → fktsigner)
    Basis for the bootable USB / GUI stack (tiny secure Linux live env).
    Same crypto path as DOS; richer TTY/QR host conveniences.
    Floppy size budget does NOT apply to the unstripped host Linux binary.

Ice Cold default: no seed-file / encrypt paths. Seed every run.

Signing pipeline modules
------------------------
  fkt_psbt.c / .h
    Load (file / base64 / memory), strict parse, state, script-type detect.
    Proprietary BIP174 0xFC accept on global / input / output (length caps;
    not interpreted; remains in psbt_buffer for sign round-trip).

  fkt_sighash.c / .h
    BIP-143 (P2WPKH / nested / P2WSH), BIP-341 keypath + scriptpath,
    hash caches over loaded unsigned tx + UTXOs.

  fkt_signer.c / .h
    Derive keys (BIP32), ECDSA / Schnorr sign, insert partial_sig / tap sig,
    cleanup maps (does NOT strip 0xFC), call finalizer.

  fkt_finalizer.c / .h
    Build final scriptWitness / scriptSig when single-sig complete.

Crypto building blocks (static libsecp256k1 + local)
----------------------------------------------------
  fkt_bip39, fkt_bip32, fkt_secp256k1
  fkt_sha256, fkt_sha512, fkt_hmac, fkt_pbkdf2
  fkt_ripemd160, fkt_hash160, fkt_bech32, fkt_address
  fkt_memzero (volatile wipe)

UI / I/O (not crypto truth)
---------------------------
  main.c          CLI entry (sign / inspect / base64 / qr / TUI)
                  Ice Cold order: preview → seed → sign → binary+Base64 → optional QR
  fkt_seed.c      Interactive BIP39 entry; random 3-word verify + CONFIRM
  fkt_preview.c   Read-only tx summary (no seed)
  fkt_confirm.c   Preview-before-seed / fingerprint
  fkt_qr*.c       Dense ASCII / PBM / VGA QR
  fkt_platform.h  DOS vs Linux port layer

Verify
------
  cd cli && make test             # Step 4: full umbrella (all gates)
  cd cli && make test-psbt-core   # Step 2: parse/sign/finalize matrix
  cd cli && make test-cli-entry   # Step 3: CLI entry gate
  cd cli && make test-bip-vectors # official BIP39 seed + SHA256 empty
  cd cli && make test-multi-input # 2in/3in/mixed PASS
  cd cli && make test-silent-payments-stub  # SP path deferred boundary
  cd cli && make test-retro                 # Step 5: DOS EXE + floppy package
  # clean C89 compile (zero warnings on Ice Cold objects we own)
  # high sparrow-real: P2WPKH + P2TR keypath + mixed + 0xFC passthrough
