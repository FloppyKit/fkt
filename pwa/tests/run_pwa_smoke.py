#!/usr/bin/env python3
"""FKT offline PWA smoke: size, offline, required symbols, Phase 0 shell."""
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
    # Allow same-origin project links (gitfkt.dev footer); block CDN script/style deps
    ext_bad = [u for u in ext if "gitfkt.dev" not in u and "github.com/FloppyKit" not in u]
    failed += check("no_external_cdn", len(ext_bad) == 0, str(ext_bad[:3]))
    for s in (
        "FKT_SECP",
        "FKT_BIP32",
        "FKT_BIP39",
        "FKT_WORDLIST",
        "btnSign",
        "btnQr",
        "dropZone",
        "cHNidP",
        "qrcode",
        "mnemonicToSeedSync",
        "HDKey",
        "SIGN TRANSACTION",
        "ENTER SEED MANUALLY",
        "ENTER PSBT MANUALLY",
        "Technical Details",
        "KEYGEN",
        "CLEAR SESSION",
        "SHOW SEED QR",
        "TAP TO SCAN QR",
    ):
        failed += check("has_" + re.sub(r"\W+", "_", s)[:28], s in text, "")
    # must NOT ship demo chrome
    for s in ("SIMULATE SEED", "SIMULATE PSBT", "sign-confirm", "Type CONFIRM", "btnSeedVerify"):
        failed += check("no_" + re.sub(r"\W+", "_", s)[:28], s not in text, "")
    # CRT theme (green accents)
    failed += check(
        "crt_green",
        "#3dff7a" in text or "--crt-hi: #3dff7a" in text or "--crt-hi:#3dff7a" in text,
        "",
    )
    failed += check("no_alpha_banner", "ALPHA · TESTNET" not in text, "")
    failed += check("camera_svg", "M14.5 4h-5L7 7H4" in text, "")
    failed += check("entropy_bar_100", "Math.min(r, 100)" in text or "Math.min(r,100)" in text, "")
    failed += check("no_main_menu", "MAIN MENU" not in text, "")
    failed += check("no_footer_status_bar", "foot-seed" not in text, "")
    print("-" * 50)
    if failed:
        print("PWA smoke FAIL", failed)
        return 1
    print("PWA smoke PASS")
    print("Open: file://%s  or  cd pwa && python3 -m http.server 8765" % HTML)
    return 0


if __name__ == "__main__":
    sys.exit(main())
