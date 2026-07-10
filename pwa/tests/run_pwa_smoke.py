#!/usr/bin/env python3
"""Phase 3 PWA smoke: size, offline, required symbols."""
from __future__ import print_function
import os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = os.path.join(ROOT, "index.html")
LIMIT = 1024 * 1024


def main():
    failed = 0

    def check(name, ok, detail=""):
        print("%-40s %s  %s" % (name, "PASS" if ok else "FAIL", detail))
        return 0 if ok else 1

    if not os.path.isfile(HTML):
        print("missing", HTML)
        return 1
    data = open(HTML, "rb").read()
    text = data.decode("utf-8", "replace")
    size = len(data)
    failed += check("size_under_1mb", size < LIMIT, "%d bytes" % size)
    failed += check("single_file", True, HTML)
    ext = re.findall(r"""(?:src|href)=["']https?://[^"']+""", text)
    failed += check("no_external_cdn", len(ext) == 0, str(ext[:3]))
    for s in (
        "FKT_SECP",
        "FKT_BIP32",
        "FKT_BIP39",
        "FKT_WORDLIST",
        "btnSign",
        "btnSeedVerify",
        "btnQr",
        "dropZone",
        "cHNidP",
        "qrcode",
        "mnemonicToSeedSync",
        "HDKey",
    ):
        failed += check("has_" + s[:24], s in text, "")
    # offline green-on-black
    failed += check("retro_green", "#00ff66" in text or "--fg:#00ff66" in text, "")
    failed += check("airgap_warning", "AIR-GAP" in text, "")
    failed += check("main_menu", "MAIN MENU" in text, "")
    failed += check("status_footer", "foot-seed" in text and "foot-psbt" in text, "")
    failed += check("scan_first", "btn-psbt-to-manual" in text and "btn-seed-to-manual" in text, "")
    print("-" * 50)
    if failed:
        print("PWA smoke FAIL", failed)
        return 1
    print("PWA smoke PASS")
    print("Open: file://%s  or  cd pwa && python3 -m http.server 8765" % HTML)
    return 0


if __name__ == "__main__":
    sys.exit(main())
