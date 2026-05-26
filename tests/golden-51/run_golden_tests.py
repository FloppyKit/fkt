#!/usr/bin/env python3
"""
run_golden_tests.py
===================

Drive the FKT signer over every PSBT in ``unsigned/`` and compare the
output to the matching ``golden-signed/`` reference.

This is a stub today: the golden directory is still empty, so the
runner just reports SKIP for every case. As soon as a golden file
lands, the same case starts producing PASS / FAIL / XFAIL / XPASS.

Usage::

    python3 run_golden_tests.py [--fktsigner ../../fktsigner] [--verbose]

Exit status::

    0   no unexpected results
    1   one or more unexpected FAIL or XPASS
    2   could not invoke the signer at all

Outcomes
--------
    PASS    fkt output bytes-equal golden, case not marked xfail
    FAIL    fkt output mismatched golden, case not marked xfail
    XFAIL   fkt failed to sign (or mismatched), case marked xfail
    XPASS   fkt output bytes-equal golden, case marked xfail
            (treat as a green flag to remove the xfail tag)
    SKIP    no golden file present yet
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Reuse the case table so xfail flags stay in lockstep with the generator.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import generate_golden_psbts as g     # noqa: E402

TEST_MNEMONIC = g.TEST_MNEMONIC
UNSIGNED_DIR = HERE / "unsigned"
GOLDEN_DIR = HERE / "golden-signed"
DEFAULT_FKTSIGNER = HERE.parent.parent / "fktsigner"

# PSBT input-map keys that carry signature material. Differences here
# count as a real FAIL; differences elsewhere trigger only a warning.
SIG_KEYS = {0x02, 0x08, 0x13, 0x14}


# --------------------------------------------------------------------------
# Tiny PSBT walker (no dependencies; mirrors fkt_psbt.c style)
# --------------------------------------------------------------------------
def _read_varint(buf: bytes, off: int) -> Tuple[int, int]:
    v = buf[off]
    off += 1
    if v < 0xFD:
        return v, off
    if v == 0xFD:
        return int.from_bytes(buf[off:off + 2], "little"), off + 2
    if v == 0xFE:
        return int.from_bytes(buf[off:off + 4], "little"), off + 4
    return int.from_bytes(buf[off:off + 8], "little"), off + 8


def extract_input_sig_kv(psbt_blob: bytes) -> List[Dict[bytes, bytes]]:
    """Return per-input dict of signature-bearing key→value pairs.

    Survives proprietary keys, Sparrow metadata, etc. Returns one dict
    per input map. Skips global and output sections.
    """
    if psbt_blob[:5] != b"psbt\xff":
        raise ValueError("not a PSBT")
    pos = 5
    # Skip globals
    while psbt_blob[pos] != 0:
        klen, pos = _read_varint(psbt_blob, pos)
        pos += klen
        vlen, pos = _read_varint(psbt_blob, pos)
        pos += vlen
    pos += 1
    # Read input maps until separator
    inputs: List[Dict[bytes, bytes]] = []
    cur: Dict[bytes, bytes] = {}
    while pos < len(psbt_blob):
        if psbt_blob[pos] == 0:
            inputs.append(cur)
            cur = {}
            pos += 1
            # Once we hit an output map (any non-input key), stop early.
            # A simple heuristic: peek next byte — if it's 0 we're done.
            if pos < len(psbt_blob) and psbt_blob[pos] == 0:
                break
            continue
        klen, pos = _read_varint(psbt_blob, pos)
        key = psbt_blob[pos:pos + klen]
        pos += klen
        vlen, pos = _read_varint(psbt_blob, pos)
        val = psbt_blob[pos:pos + vlen]
        pos += vlen
        if klen >= 1 and key[0] in SIG_KEYS:
            cur[key] = val
    return inputs


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------
@dataclass
class Outcome:
    case: g.Case
    state: str          # PASS / FAIL / XFAIL / XPASS / SKIP / ERROR
    detail: str = ""


def compare(fkt_blob: bytes, golden_blob: bytes,
            verbose: bool) -> Tuple[bool, str]:
    """Return (equal, message)."""
    if fkt_blob == golden_blob:
        return True, "exact byte match"
    fkt_in = extract_input_sig_kv(fkt_blob)
    gold_in = extract_input_sig_kv(golden_blob)
    if fkt_in == gold_in:
        return True, "signature fields match (metadata differs)"
    msg = ["signature fields differ:"]
    for i, (a, b) in enumerate(zip(fkt_in, gold_in)):
        only_fkt = sorted(set(a) - set(b))
        only_gold = sorted(set(b) - set(a))
        if only_fkt:
            msg.append(f"  input {i} only in fkt: "
                       f"{[k.hex() for k in only_fkt]}")
        if only_gold:
            msg.append(f"  input {i} only in golden: "
                       f"{[k.hex() for k in only_gold]}")
        for k in set(a) & set(b):
            if a[k] != b[k]:
                msg.append(f"  input {i} key {k.hex()} differs")
                if verbose:
                    msg.append(f"    fkt:    {a[k].hex()}")
                    msg.append(f"    golden: {b[k].hex()}")
    return False, "\n".join(msg)


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------
def run_case(case: g.Case, fktsigner: Path,
             verbose: bool) -> Outcome:
    unsigned = UNSIGNED_DIR / f"{case.name}.psbt"
    golden = GOLDEN_DIR / f"{case.name}.psbt"
    if not unsigned.exists():
        return Outcome(case, "SKIP", "no unsigned PSBT (run generator)")
    if not golden.exists():
        return Outcome(case, "SKIP", "no golden file yet")

    with tempfile.NamedTemporaryFile("wb", suffix=".psbt", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        proc = subprocess.run(
            [str(fktsigner), "sign", str(unsigned),
             str(tmp_path), TEST_MNEMONIC],
            capture_output=True, text=True, timeout=15,
        )
    except FileNotFoundError:
        tmp_path.unlink(missing_ok=True)
        raise
    except subprocess.TimeoutExpired:
        tmp_path.unlink(missing_ok=True)
        return Outcome(case, "ERROR", "fktsigner timed out")

    fkt_blob = tmp_path.read_bytes() if tmp_path.exists() else b""
    tmp_path.unlink(missing_ok=True)

    if proc.returncode != 0 or not fkt_blob:
        if case.xfail:
            return Outcome(case, "XFAIL",
                           f"signer rc={proc.returncode}; expected to fail")
        return Outcome(case, "FAIL",
                       f"signer rc={proc.returncode}\n"
                       f"stdout: {proc.stdout.strip()}\n"
                       f"stderr: {proc.stderr.strip()}")

    golden_blob = golden.read_bytes()
    eq, detail = compare(fkt_blob, golden_blob, verbose)
    if eq:
        return Outcome(case, "XPASS" if case.xfail else "PASS", detail)
    return Outcome(case, "XFAIL" if case.xfail else "FAIL", detail)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--fktsigner", type=Path, default=DEFAULT_FKTSIGNER,
                   help=f"path to fktsigner binary (default {DEFAULT_FKTSIGNER})")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="show byte-level diffs on mismatch")
    p.add_argument("--filter", default=None,
                   help="only run cases whose name contains this substring")
    args = p.parse_args(argv)

    if not args.fktsigner.exists():
        sys.stderr.write(f"error: fktsigner not found at {args.fktsigner}\n"
                         f"build it first (run `make` in the project root) "
                         f"or pass --fktsigner.\n")
        return 2

    cases = g.CASES
    if args.filter:
        cases = [c for c in cases if args.filter in c.name]

    outcomes: List[Outcome] = []
    for case in cases:
        try:
            outcomes.append(run_case(case, args.fktsigner, args.verbose))
        except FileNotFoundError:
            sys.stderr.write(f"error: cannot exec {args.fktsigner}\n")
            return 2

    width = max(len(c.name) for c in cases) if cases else 4
    counts = {"PASS": 0, "FAIL": 0, "XFAIL": 0, "XPASS": 0,
              "SKIP": 0, "ERROR": 0}
    for o in outcomes:
        counts[o.state] += 1
        suffix = ""
        if o.state in ("FAIL", "XPASS", "ERROR"):
            suffix = f"  -- {o.detail.splitlines()[0]}"
        elif args.verbose and o.detail:
            suffix = f"  -- {o.detail.splitlines()[0]}"
        print(f"{o.state:<6} {o.case.name:<{width}}{suffix}")
        if args.verbose and o.state in ("FAIL", "XPASS"):
            for line in o.detail.splitlines()[1:]:
                print(f"       {line}")

    print()
    print("  ".join(f"{k}={v}" for k, v in counts.items()
                    if v or k in ("PASS", "FAIL")))
    bad = counts["FAIL"] + counts["XPASS"] + counts["ERROR"]
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
