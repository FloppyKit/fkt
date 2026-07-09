#!/usr/bin/env python3
"""List sparrow-real matrix cases from manifest.json (layout work package).

Usage:
  python3 tests/sparrow_real_list.py           # high priority only
  python3 tests/sparrow_real_list.py --all     # every case
  python3 tests/sparrow_real_list.py --check   # verify files exist (exit 1 on missing)
"""
from __future__ import print_function

import argparse
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(SCRIPT_DIR, "sparrow-real")
MANIFEST = os.path.join(ROOT, "manifest.json")


def load_manifest():
    with open(MANIFEST, "r") as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser(description="List FKT sparrow-real matrix cases")
    ap.add_argument("--all", action="store_true", help="List all priorities (default: high only)")
    ap.add_argument("--check", action="store_true", help="Verify fixture paths exist")
    ap.add_argument("--priority", default=None, help="Filter by priority (high|medium|low|bonus)")
    args = ap.parse_args()

    if not os.path.isfile(MANIFEST):
        print("ERROR: missing %s" % MANIFEST, file=sys.stderr)
        return 1

    man = load_manifest()
    cases = man.get("cases") or []
    if args.priority:
        cases = [c for c in cases if c.get("priority") == args.priority]
    elif not args.all:
        cases = [c for c in cases if c.get("priority") == "high"]

    if not cases:
        print("ERROR: no cases matched filter", file=sys.stderr)
        return 1

    missing = 0
    print("sparrow-real matrix (%d cases)  network=%s" % (
        len(cases), man.get("network", "?")))
    print("%-42s %-12s %-10s %-22s %s" % (
        "id", "expect", "priority", "seed_ref", "unsigned"))
    print("-" * 110)

    for c in cases:
        cid = c.get("id", "?")
        expect = c.get("expect", "?")
        pri = c.get("priority", "?")
        seed = c.get("seed_ref", "?")
        upath = c.get("unsigned") or ""
        full_u = os.path.join(ROOT, upath) if upath else ""
        ok_u = os.path.isfile(full_u) if full_u else False
        flag = ""
        if args.check:
            if not ok_u:
                flag = " MISSING unsigned"
                missing += 1
            else:
                flag = " ok"
            sref = c.get("sparrow_signed")
            if sref:
                full_s = os.path.join(ROOT, sref)
                if not os.path.isfile(full_s):
                    flag += " MISSING sparrow_signed"
                    missing += 1
        print("%-42s %-12s %-10s %-22s %s%s" % (
            cid, expect, pri, seed, upath, flag))

    high_total = sum(1 for c in (man.get("cases") or []) if c.get("priority") == "high")
    print("-" * 110)
    print("high priority in manifest: %d" % high_total)
    if args.check and missing:
        print("ERROR: %d missing file(s)" % missing, file=sys.stderr)
        return 1
    if not args.all and not args.priority:
        if high_total < 1:
            print("ERROR: no high-priority cases", file=sys.stderr)
            return 1
        print("PASS: high-priority cases listed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
