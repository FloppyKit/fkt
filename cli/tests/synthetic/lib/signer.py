import subprocess, os

SIGNER_BIN = os.path.join(os.path.dirname(__file__), "..", "..", "..", "fktsigner")
SEED_HEX   = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
DERIV_PATH = "84'/1'/0'/0/0"

def get_pubkey():
    """Return the compressed pubkey hex string derived from the default seed/path."""
    res = subprocess.run(
        [SIGNER_BIN, "--pubkey", SEED_HEX, DERIV_PATH],
        capture_output=True, text=True, check=True
    )
    return res.stdout.strip()

def sign(unsigned_file, signed_file):
    """Sign a PSBT. Returns True on success, False on failure."""
    ret = subprocess.run(
        [SIGNER_BIN, SEED_HEX, DERIV_PATH, unsigned_file, signed_file],
        capture_output=True
    )
    return ret.returncode == 0