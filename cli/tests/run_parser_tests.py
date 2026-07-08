#!/usr/bin/env python3
"""
Simple test runner for the FKT PSBT parser.
Walks all .psbt files in tests/golden-51/unsigned/ and runs
a small parse‑only test binary against each one.

Usage:
    python3 tests/run_parser_tests.py [--binary PATH] [--verbose | -v]

The test binary (psbt_parse_test) must be compiled via ``make test-parse``.
See tests/psbt_parse_test.c for the source.
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path

UNSIGNED_DIR = "tests/golden-51/unsigned"

# Known-invalid corpus entries (sighash variants, conflicting UTXO, mixed deferred).
EXPECTED_FAIL = {
    "mixed_p2sh_p2wpkh_p2tr_2in_2out.psbt",
    "mixed_p2wpkh_p2tr_2in_2out.psbt",
    "mixed_p2wsh_p2tr_2in_2out.psbt",
    "p2tr_keypath_all_1in_2out.psbt",
    "p2tr_keypath_all_acp_1in_2out.psbt",
    "p2tr_keypath_none_1in_2out.psbt",
    "p2tr_keypath_single_1in_2out.psbt",
    "p2wpkh_all_acp_1in_2out.psbt",

    "p2wpkh_none_1in_2out.psbt",
    "p2wpkh_single_1in_2out.psbt",
}

def run_test(binary_path, filepath, verbose=False):
    cmd = [binary_path, str(filepath)]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5
        )
    except subprocess.TimeoutExpired:
        return ("ERROR", "timeout (>5s)", None)
    except FileNotFoundError:
        return ("ERROR", f"test binary '{binary_path}' not found", None)
    except Exception as e:
        return ("ERROR", f"unexpected exception: {e}", None)

    if result.returncode == 0:
        return ("PASS", "", None)

    if result.returncode == 1:
        msg = result.stderr.strip()
        first_line = msg.split('\n')[0] if msg else "unknown error"
        return ("FAIL", first_line, None)

    msg = f"exit code {result.returncode}"
    if result.stderr:
        msg += f"; stderr: {result.stderr[:120]}"
    return ("ERROR", msg, None)

def main():
    parser = argparse.ArgumentParser(description="FKT PSBT parser smoke tests")
    parser.add_argument("-b", "--binary", default="./psbt_parse_test",
                        help="path to the psbt_parse_test binary (default: ./psbt_parse_test)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="on failure, print full parser stderr and stdout")
    args = parser.parse_args()

    unsigned_path = Path(UNSIGNED_DIR)
    if not unsigned_path.is_dir():
        print(f"ERROR: directory '{UNSIGNED_DIR}' not found")
        sys.exit(1)

    psbt_files = sorted(unsigned_path.rglob("*.psbt"))
    if not psbt_files:
        print(f"ERROR: no .psbt files found in {UNSIGNED_DIR}")
        sys.exit(1)

    stats = {"PASS": 0, "FAIL": 0, "ERROR": 0}
    unexpected = 0
    longest_name = max(len(str(f.relative_to(unsigned_path))) for f in psbt_files)

    for f in psbt_files:
        rel_path = f.relative_to(unsigned_path)
        rel_name = str(rel_path)
        status, msg, _preview_lines = run_test(args.binary, f,
                                               verbose=args.verbose)

        line = f"{status:<6} {rel_path}"
        if status != "PASS" and msg:
            line += f"  -- {msg}"
        if status == "FAIL" and rel_name not in EXPECTED_FAIL:
            unexpected += 1
        if status == "PASS" and rel_name in EXPECTED_FAIL:
            unexpected += 1
            line += "  -- unexpected PASS"
        print(line)

        if args.verbose and status != "PASS":
            verbose_cmd = [args.binary, str(f)]
            verbose_run = subprocess.run(
                verbose_cmd,
                capture_output=True, text=True, timeout=5
            )
            if verbose_run.stdout:
                print("    stdout:", verbose_run.stdout.strip()[:200])
            if verbose_run.stderr:
                print("    stderr:", verbose_run.stderr.strip()[:400])
            print("")

        stats[status] += 1

    total = sum(stats.values())
    print(f"\nPASS={stats['PASS']}  FAIL={stats['FAIL']}  ERROR={stats['ERROR']}  TOTAL={total}")
    if stats["ERROR"] > 0 or unexpected > 0:
        print(f"Unexpected results: {unexpected}  (expected FAIL={len(EXPECTED_FAIL)})")
        sys.exit(1)

if __name__ == "__main__":
    main()