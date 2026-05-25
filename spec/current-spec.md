You are a paranoid, battle-hardened Bitcoin protocol engineer who has personally audited multiple PSBT signers and offline wallets. Your job is to find every possible way this signer can lose user funds, accept malformed data, create subtle security holes, or violate the project's strict constraints. You are vicious, extremely detailed, and pessimistic. You assume the worst.

Project: FKT — Floppy Kit Tool
Core Philosophy: "Any old junk can sign Bitcoin." We are building an extremely minimal, offline, stateless PSBT signer that must run on 1992-era hardware and fit on a 1.44 MB floppy. The entire tool must feel like it could have existed in 1995 but still signs real mainnet PSBTs correctly today.

Non-Negotiable Rules (never violate these):
- Strict ANSI C89 only. All types come exclusively from fkt_compat.h.
- Only dependency: static libsecp256k1 + our own fkt_crypto (SHA512, PBKDF2-HMAC-SHA512, HMAC, SHA256, etc.).
- Stateless: seed is entered every run, never stored.
- Preview + hash confirmation must happen BEFORE any seed is read or any key material is in memory.
- Hard abort + loud clear error on ANY malformed PSBT, bounds violation, duplicate key, txid mismatch, negative fee, unsupported script type, etc. We refuse to sign garbage.
- Maximum paranoia + minimum code. "Signing Perfect First".
- All sensitive memory must be securely zeroed with volatile loops on every path (including aborts).
- The PSBT is read ONCE into a static in-memory buffer. All operations use that same buffer. Never re-read from disk.
- No dynamic memory allocation (malloc, calloc, free) shall be used; all working memory is static.

**1. INPUT HANDLING (explicit only — no auto-detection)**
- Command: fkt sign --file <path> | --base64 <string> | --hex <string> [--path m/84'/0'/0'/0/0] [--output signed.psbt]
- Exactly one input flag must be provided.
- Before decoding Base64 or hex, enforce string length limit (e.g., 2 MB raw string) to prevent DoS on 1992 hardware.
- Validate path is a regular file (stat/lstat check) before opening. No symlink or device file allowed.
-
**2. PARSER / PREVIEW (strict read-only)**
- PSBT magic must be exactly 0x70 0x73 0x62 0x74 0xFF (the ASCII bytes 'p','s','b','t' followed by 0xFF). Abort on any mismatch.
- Verify that the byte immediately following the four magic bytes is 0xFF. Abort otherwise.
- The unsigned transaction must be serialized in legacy (non-segwit) format. Abort with "Unsigned tx must not contain witness data" if bytes at offset 4–5 from the start of the transaction value are 0x00 0x01 (segwit marker and flag).
- Walk input maps: witness_utxo first → non_witness_utxo with full txid verification (double-SHA256 of the non-witness serialization).
- Walk output maps: exact count match, no duplicates. The number of per-input PSBT maps must exactly equal the number of inputs in the unsigned tx; the number of per-output PSBT maps must exactly equal the number of outputs in the unsigned tx. Abort otherwise.
- Input script type detection is scriptPubKey-primary from witness_utxo:
  - P2WPKH: exactly 0x00 0x14 <20-byte hash> (exactly 22 bytes total)
  - Taproot keypath: exactly 0x51 0x20 <32-byte x-only> (exactly 34 bytes total)
- Taproot detection: key 0x17 must be present. If missing on a Taproot input, abort with “Taproot input missing PSBT_IN_TAP_INTERNAL_KEY”.
- Classification order: scriptPubKey from witness_utxo first, then apply the SIGHASH_TYPE (0x03) rule.
- Varint parsing: abort on non-minimal varints or declared length that would exceed the buffer. If key_len == 0 and not a map boundary, abort with “zero-length key”.
- All Bitcoin integer fields must be deserialized using fkt_read_le16/32/64.
- All serialisation of new PSBT data (key lengths, value lengths, witness element counts, etc.) must use the corresponding fkt_write_le16/32/64 functions.
- Static buffer is at least 1.5 MB. Abort with “PSBT too large” if input exceeds this size.
- Unsigned tx serialization size ≤ 100 KB or abort with “Unsigned tx too large”.
- Enforce exact PSBT separators: exactly one `0x00` byte after the global map, after each input map, after each output map, and after the final output map. After the final separator the buffer must be exhausted (no trailing data). Abort on any missing, extra, or misplaced separators.
- Abort on: duplicate keys, count mismatch, script >520 bytes (inputs only), vout out of bounds, txid mismatch, malformed UTXO, negative fee, trailing data, non-minimal varints, 0-input/0-output transactions, unsupported input script type (only P2WPKH and Taproot keypath allowed), missing verifiable amount on any input, pre-existing witness data (key 0x08 or 0x07 with non-empty value), unsigned transaction version not 1 or 2, etc.
- Exactly one of 0x00 or 0x01 must be present per input. If both are present, abort with “Conflicting UTXO data”.
- Abort if any outpoint (txid + vout) appears more than once across all inputs.
- During unsigned tx parsing: for each input abort if scriptSig length != 0.
- For key 0x01 (witness_utxo): abort if value length < 8 or if the scriptPubKey length exceeds the remaining bytes or if the scriptPubKey in a witness UTXO exceeds 10,000 bytes. Enforce ≤ 520 bytes maximum for all input scriptPubKeys uniformly.
- For key 0x17 (Taproot internal key): abort if value length != 32.
- For key 0x16 (PSBT_IN_TAP_BIP32_DERIVATION): before skipping any fields, verify that the value length is at least 1 + (num_leaf_hashes * 32) + 4 bytes (with num_leaf_hashes parsed from the first varint). Abort immediately if insufficient. Use safe integer arithmetic that detects overflow (or restrict num_leaf_hashes to a sane maximum e.g. 256 and abort if exceeded). Verify that the remaining bytes are a multiple of 4 and exactly 20 bytes (5 indices); abort otherwise.
- For key 0x06 (BIP32 derivation — used for path comparison when no --path override): parse as 4-byte fingerprint + path (multiple of 4 bytes). Abort if value length < 4 or (value length – 4) is not a multiple of 4. Ensure the parsed path has exactly 5 indices (20 bytes after fingerprint). Validate that each index is within BIP32 range.
- After parsing the unsigned transaction, verify that all bytes of the value have been consumed; abort otherwise.
- Abort if any non_witness_utxo (key 0x00) value exceeds 100 KB.
- Fee = sum of all verifiable input amounts minus sum of all output amounts (safe comparison to avoid unsigned wrap-around). Abort if negative or if any input amount is missing. Before any mutation, compute the maximum possible final transaction weight assuming the largest valid signature (74 bytes for P2WPKH, 64 bytes for Schnorr), including all varint overhead for witness items (1 byte key length 0x01, 1 byte key 0x08, varint for value length, then the witness stack encoding). Then derive vbytes = ceil(weight / 4), and abort if fee / vbytes > 10,000.
- For unrecognised output scripts: display hex dump + label “OP_RETURN” or “non-standard”. P2PKH and P2SH outputs are displayed with their base58check address if the implementation includes a base58 encoder (fixed-length buffer, overflow check); otherwise display hex + label “P2PKH (legacy)” or “P2SH”.
- Abort if any output scriptPubKey > 10,000 bytes.
- Compute and display full PSBT SHA256. Label as “PSBT fingerprint (for confirmation)”. Separately compute and display the actual unsigned txid (double-SHA256 of the non-witness serialized transaction).
- Display nLockTime (and note if > 0) and all nSequence values; flag any input with nSequence ≤ 0xFFFFFFFD as RBF-enabled.
- All preview data structures (input/output arrays, BIP32 path buffers, address strings) shall be declared as static globals, never local variables, to avoid stack overflow on 1992-era hardware.
- Maximum inputs: 256. Maximum outputs: 64. Abort immediately if exceeded.
- Maximum keys-per-map: 32 for inputs, 16 for outputs. Abort if exceeded.
- Explicit PSBT key whitelist:
  - Global map: `0x00` only (this spec targets PSBTv0 only; PSBTv2 global keys abort as unknown).
  - Per-input map: `0x00` (non-witness UTXO), `0x01` (witness UTXO), `0x03` (SIGHASH_TYPE — for P2WPKH key 0x03 may be absent (treated as 0x01) or exactly 0x01; for Taproot it may be absent (treated as 0x00) or present with exactly 0x00; any other value aborts; value must be exactly 4 bytes when present. Read with fkt_read_le32. Abort if value length ≠ 4), `0x06` (BIP32 derivation — parse for path), `0x07` (final scriptsig — abort if present and value length > 0), `0x08` (witness stack — abort if present regardless of value length), `0x16` (PSBT_IN_TAP_BIP32_DERIVATION — parse for path), `0x17` (Taproot internal key), `0x18` (PSBT_IN_TAP_MERKLE_ROOT — abort if present).
  - Per-output map: ignore unknown keys (only count and no-duplicate checks are performed).
  Any key not in the whitelist above aborts with “Unknown PSBT key”.
- Key field length validation: Key 0x06 must have key field length exactly 34 (type byte + 33-byte compressed pubkey); abort if not. Key 0x16 must have key field length exactly 33 (type byte + 32-byte x-only pubkey); abort if not. Keys 0x00, 0x01, 0x03, 0x07, 0x08, 0x17, 0x18 must have key field length exactly 1 (type byte only); abort if not.
- If both key 0x06 and key 0x16 are present in the same input map, abort with “Conflicting derivation keys”.
- V0.1 supports Taproot keypath spending only for addresses created without a script tree (PSBT_IN_TAP_MERKLE_ROOT must be absent). Taproot addresses with an associated taptree cannot be signed in V0.1 even via the keypath.

**3. SEED PHRASE INPUT & VERIFICATION**
- Only after preview + hash confirmation.
- Word-by-word entry with live BIP39 validation (re-prompt until canonical).
- Full review/edit pass.
- Full BIP39 checksum.
- Final full re-type of the entire seed phrase (byte-wise comparison).
- Use a constant-time memory comparison for the two seed phrase buffers.
- If the two copies do not match, abort immediately, zero both buffers, and print “Seed verification failed”.
- Volatile-zero both the entry buffer and the confirmation buffer immediately before proceeding or aborting.
- Volatile-zero raw mnemonic immediately after PBKDF2.
- Only English BIP39 wordlist supported. Non-ASCII input aborts.
- V0.1 does not support optional passphrase.
- PBKDF2-HMAC-SHA512 uses exactly 2048 iterations.
- After computing the master private key, abort if it is zero or ≥ SECP256K1_ORDER.

**4. BIP32 DERIVATION**
- CLI --path override first.
- If no override: every input must contain a usable derivation key (0x06 or 0x16), and all of them must be byte-for-byte identical after parsing the path (for 0x16 skip varint(num_leaf_hashes) + (num_leaf_hashes * 32) bytes, then skip fingerprint, then compare only the remaining path bytes). Abort if any input is missing a usable derivation key or paths differ.
- The derivation path must start with `m/`, consist of exactly 5 indices separated by `/`. The first three indices must be hardened. The last two indices (change + address index) may be hardened or non-hardened. Abort with “Derivation path must be fully hardened for the first three indices” if any of the first three is missing the tick.
- Derive all five levels strictly according to the hardening flag (hardened if followed by `'`).
- When deriving from PSBT fields (0x06 or 0x16), an index is hardened if its value ≥ 0x80000000.
- Abort if any parsed decimal path index value > 2,147,483,647 before the hardened bit is applied.
- Zero master keys immediately after child_priv is derived.
- All key material buffers (child_priv, master seed, mnemonic) are static globals.
- Multi-path PSBTs (different derivation paths per input) are out of scope for V0.1 and will be added in V0.2.
- If secp256k1 child key derivation fails, abort with “BIP32 child key derivation failed”.

**5. SIGNING + PSBT FINALIZER**
- The following values are computed **once over all inputs/outputs before the signing loop** and cached in static globals: hashPrevouts = dSHA256(all outpoints concatenated in input order); hashSequence = dSHA256(all nSequences as 4-byte LE in input order); sha_prevouts = SHA256(same); sha_amounts = SHA256(all input amounts as 8-byte LE in input order); sha_scriptpubkeys = SHA256(all input scriptPubKeys each preceded by their varint-encoded byte length); sha_sequences = SHA256(all nSequences as 4-byte LE in input order); sha_outputs = SHA256(all outputs fully serialized); hashOutputs = dSHA256(all outputs fully serialized in CTxOut format). These are reused for every input in the signing loop.
- For each input, the amount used in sha_amounts and fee computation is: if key 0x01 (witness_utxo) is present, the 8-byte little-endian value at bytes [0..7] of that entry; if key 0x00 (non_witness_utxo) is present, the value field of output number vout within the parsed transaction (the vout-th CTxOut, zero-indexed). These amounts are extracted during the preview phase and stored in the static global array fkt_input_amounts[256].
- All inputs must match the single derived key (derived internal key matches PSBT 0x17 for Taproot or derived pubkey matches witness program for P2WPKH). If *any* input does not match, hard abort with “Input does not belong to this seed/path”.
- For each matching input:
  - P2WPKH → BIP143 sighash (with explicit preimage fields):
    - nVersion (4 bytes LE)
    - hashPrevouts (32 bytes)
    - hashSequence (32 bytes)
    - outpoint (36 bytes)
    - scriptCode (0x19 0x76 0xa9 0x14 <20-byte hash160 from witness_utxo scriptPubKey bytes [2..21]> 0x88 0xac)
    - amount (8 bytes LE)
    - nSequence (4 bytes LE)
    - hashOutputs (32 bytes)
    - nLockTime (4 bytes LE)
    - sighash type = 0x01 (SIGHASH_ALL)
  - Taproot keypath → BIP341 sighash (with explicit preimage fields):
    - epoch = 0x00 (first byte, always)
    - hash_type = 0x00 (SIGHASH_DEFAULT for Taproot keypath)
    - nVersion
    - nLockTime
    - sha_prevouts
    - sha_amounts
    - sha_scriptpubkeys
    - sha_sequences
    - sha_outputs
    - spend_type (0x00 for keypath)
    - input_index (4 bytes LE)
- Explicit public-key verification before signing:
  - P2WPKH: Extract 20-byte witness program from scriptPubKey (0x00 0x14 <hash>). Compute hash160(derived_pubkey). Constant-time compare. Abort on mismatch.
  - Taproot keypath: Extract 32-byte internal key from PSBT_IN_TAP_INTERNAL_KEY. Verify that the derived internal key (from path) matches the PSBT value. If the internal public key has odd y, negate child_priv (`child_priv = SECP256K1_ORDER - child_priv`). Compute tweak = tagged_hash("TapTweak", internal_key[32]). Interpret the 32-byte tagged hash output as a 256-bit big-endian unsigned integer tweak_int. Abort with 'Invalid Taproot tweak' if tweak_int >= SECP256K1_ORDER. Compute d' = (d + tweak) mod n. Let Q = d'*G. If Q has odd y, set d' = n - d'. Constant-time compare x-only bytes to witness program (0x51 0x20 <32 bytes>). Abort on mismatch.
- Sign (ECDSA with RFC6979 deterministic nonces; Schnorr with built-in BIP340 deterministic nonce). For Taproot, the child_priv is tweaked with the BIP341 tweak before signing. After tweaking, verify the resulting private key is valid (non-zero and < curve order). Abort on failure.
- Build witness stack:
  - P2WPKH: [ DER_signature + 0x01 (74 bytes max), 33-byte compressed pubkey ]
  - Taproot keypath: [ 64-byte raw Schnorr signature ]
- Before any mutation, compute conservative maximum final size (original size + max witness per input: 113 bytes for P2WPKH, 69 bytes for Taproot). Abort with “Signed PSBT too large for buffer” if it would exceed the static buffer.
- Insert witness stack (key 0x08) into the same in-memory buffer using exact varint serialization: varint(stack_items) || [varint(len_item) || item] for each item.
- For P2WPKH inputs, do not write key 0x07 (empty scriptsig is omitted per BIP174).
- Hard abort on any failure.
- The sighash preimage assembly buffer shall be a static global of at least 256 bytes.

**6. OVERALL CLI FLOW + OUTPUT + ZEROING**
- Re-verify PSBT hash right before signing. Recompute SHA256 of the entire PSBT buffer and compare byte-for-byte to the stored static fingerprint. Abort with 'PSBT buffer integrity check failed' on mismatch.
- After signing: parse signed PSBT and require final confirmation of all outputs + final TXID before writing to disk. The TXID for post-signing confirmation is computed as double-SHA256 of the value bytes of global key 0x00 (the unsigned transaction), which is unmodified by signing. Re-derive addresses and TXID from scratch (independent of cached preview data). Post-signing confirmation reads addresses and amounts from the unsigned tx (global key 0x00) and the output scriptPubKeys only. It does not re-parse per-input PSBT maps.
- On success: compute Base64 + dense ASCII QR + write signed.psbt (with overwrite prompt if file exists).
  - Display the full output path prominently before and after signing.
  - QR generation is a usability feature for the retro PWA and old hardware compatibility; it adds code size but is not security-critical. It may be made optional or removed in a future minimal build. If base64 PSBT > 1 KB, warn user that QR may be too large for terminal.
- For input: open with O_RDONLY | O_NOFOLLOW (if available) or after open use fstat to verify S_ISREG and inode/device match prior lstat. For output: use O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW or perform post-open fstat verification.
- Install a simple SIGINT handler that sets a global flag; the main loop exits via the single cleanup path. Check the SIGINT flag after every input operation (file read, character read, user prompt) and inside PBKDF2 and secp256k1 loops. If set, jump to the cleanup path immediately. On classic hardware, document that power-off is the only way to guarantee zeroing.
- On EVERY path (success or abort): volatile-zero child_priv, seed material, PSBT buffer, and all temporaries (including parsed paths, fingerprints, and transaction metadata) using a single cleanup exit path. Also zero the pre-loop hash caches (hashPrevouts, hashSequence, sha_prevouts, sha_amounts, sha_scriptpubkeys, sha_sequences, sha_outputs, hashOutputs) and the sighash preimage buffer.
- fkt_memzero must be compiled in a separate translation unit to prevent inlining and dead-store elimination.
- All comments must use /* ... */. No // comments. No inline functions. Variable declarations at the top of each block only.
- FKT V0.1 produces a signer-role PSBT. Key 0x08 is added; no other keys are removed. Downstream tools must finalize and extract before broadcasting.

**NORMATIVE APPENDIX: fkt_compat.h TYPES**
```c
typedef unsigned char      fkt_uint8_t;   /* 8 bits, always unsigned */
typedef unsigned int       fkt_uint16_t;  /* 16 bits */
typedef unsigned long      fkt_uint32_t;  /* 32 bits on all targets  */
typedef long               fkt_int32_t;   /* 32 bits signed          */
typedef unsigned long      fkt_size_t;    /* must hold 1,572,864     */

/* 64-bit type for amount arithmetic on 16/32-bit targets: */
typedef struct {
    fkt_uint32_t lo;
    fkt_int32_t  hi;
} fkt_int64_t;

## Normative Appendix: fkt_compat.h Types + Build Flags

[Insert the appendix content from the end of Chunk 6]
