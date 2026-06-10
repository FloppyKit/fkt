#!/usr/bin/env python3
import sys, subprocess
from embit.bip39 import mnemonic_to_seed

if len(sys.argv) != 5:
    print("Usage: fktsigner_wrapper.py sign <input> <output> <seed_phrase>")
    sys.exit(1)

_, cmd, infile, outfile, seed_phrase = sys.argv
if cmd != "sign":
    print("Only 'sign' subcommand is supported")
    sys.exit(1)

# Convert mnemonic to hex seed (no passphrase)
seed_bytes = mnemonic_to_seed(seed_phrase, password="")
seed_hex = seed_bytes.hex()

# Call the real signer with a dummy path (auto‑path will override)
dummy_path = "84'/1'/0'/0/0"
result = subprocess.run(
    ["./fktsigner", seed_hex, dummy_path, infile, outfile],
    cwd="/workspaces/fkt/cli"
)
sys.exit(result.returncode)