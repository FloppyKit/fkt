#!/usr/bin/env python3
"""Seed libFuzzer corpus: 17 sparrow-real unsigned + 10 malformed PSBTs."""
from __future__ import annotations

import os
import shutil
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "corpus"
SPARROW = ROOT / "tests" / "sparrow-real" / "Unsigned" / "v1"
BASE = SPARROW / "v1_p2wpkh_1in_1out.psbt"
BASE_P2TR = SPARROW / "v1_p2tr_1in_1out.psbt"


def write(name: str, data: bytes) -> None:
    path = CORPUS / name
    path.write_bytes(data)
    print(f"  corpus/{name}  ({len(data)} bytes)")


def main() -> None:
    if CORPUS.exists():
        shutil.rmtree(CORPUS)
    CORPUS.mkdir(parents=True)

    print("Sparrow-real seeds:")
    for src in sorted(SPARROW.glob("*.psbt")):
        dst = CORPUS / f"sparrow_{src.name}"
        shutil.copy2(src, dst)
        print(f"  {dst.relative_to(ROOT)}  ({dst.stat().st_size} bytes)")

    base = BASE.read_bytes()
    base_tr = BASE_P2TR.read_bytes()

    print("Malformed seeds:")
    write("mal_truncated_magic.psbt", base[:-1])
    write("mal_truncated_map.psbt", base[: max(32, len(base) // 2)])
    bad_varint = bytearray(base)
    if len(bad_varint) > 40:
        bad_varint[20:23] = b"\xff\xff\xff"
    write("mal_bad_varint.psbt", bytes(bad_varint))

    dup = bytearray(base)
    # splice duplicate global unsigned-tx key after first input separator region
    magic_end = dup.find(b"\x00\xff", 5)
    if magic_end > 0:
        insert_at = magic_end + 2
        dup[insert_at:insert_at] = b"\x01\x00"
    write("mal_duplicate_global_tx.psbt", bytes(dup))

    neg = bytearray(base)
    # inflate first output amount if we can find 8-byte LE amount after output header
    idx = neg.find(b"\x00\x02")  # 2 outputs in many vectors
    if idx > 0 and idx + 12 < len(neg):
        struct.pack_into("<Q", neg, idx + 4, 9_000_000_000_000)
    write("mal_negative_fee.psbt", bytes(neg))

    unk = bytearray(base)
    if len(unk) > 60:
        unk[50:50] = b"\x01\x99\x01\xaa"
    write("mal_unknown_psbt_key.psbt", bytes(unk))

    no_tap = bytearray(base_tr)
    key = b"\x01\x17"
    pos = 0
    while True:
        pos = no_tap.find(key, pos)
        if pos < 0:
            break
        # remove tap internal key entry (key+33-byte value) heuristically
        del no_tap[pos : pos + 2 + 33]
        break
    write("mal_missing_tap_key_0x17.psbt", bytes(no_tap))

    corrupt_fin = bytearray(base)
    fin_key = b"\x01\x08"
    pos = corrupt_fin.find(fin_key)
    if pos > 0 and pos + 6 < len(corrupt_fin):
        corrupt_fin[pos + 4] = 0xff
        corrupt_fin[pos + 5] = 0xff
    write("mal_corrupt_finalizer.psbt", bytes(corrupt_fin))

    dup_sig = bytearray(base)
    psig = b"\x22\x02"
    pos = dup_sig.find(psig)
    if pos > 0:
        end = pos + 2
        while end < len(dup_sig) and dup_sig[end] != 0:
            end += 1
        chunk = dup_sig[pos:end]
        dup_sig[pos:end] = chunk + chunk
    write("mal_duplicate_partial_sig.psbt", bytes(dup_sig))

    write("mal_magic_only.psbt", b"psbt\xff\x00")
    write("mal_empty.psbt", b"")

    total = len(list(CORPUS.iterdir()))
    print(f"\nCorpus ready: {total} files in {CORPUS.relative_to(ROOT)}/")


if __name__ == "__main__":
    main()