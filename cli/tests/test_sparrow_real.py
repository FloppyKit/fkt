#!/usr/bin/env python3
"""Real Sparrow tests — per-input paths from PSBT; sig-verify fallback."""
import hashlib
import os
import struct
import subprocess

SCRIPT_DIR = os.path.dirname(__file__)
CLI_DIR = os.path.join(SCRIPT_DIR, "..")
SIGNER_BIN = os.path.join(CLI_DIR, "fktsigner")
VERIFY_BIN = os.path.join(CLI_DIR, "verify_ecdsa")

SEEDS = {
    "v1_p2wpkh": "46b6b71e4a52ba6259aae7a9eaa991aea07fead2850cb9710aea4b234b73dcc26f21d986924ec4224f0fff3b2c73788de8e1f925451b79fcccbed9951b9b184d",
    "v1_p2tr":   "dc26536673dd2912aae6863d2984566995154dcdd72c003ebf4dc61e7b93e710e9693f23cfc397ca71bc9362cefb95ab52896d0dc68cfae352b6d8dda13aaeaa",
}

UNSIGNED_DIR = os.path.join(SCRIPT_DIR, "sparrow-real", "Unsigned", "v1")
SIGNED_DIR   = os.path.join(SCRIPT_DIR, "sparrow-real", "Signed", "v1")
OUTPUT_DIR   = os.path.join(SCRIPT_DIR, "sparrow-real", "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def read_varint(raw, pos):
    v = raw[pos]
    if v < 0xFD:
        return v, pos + 1
    if v == 0xFD:
        return raw[pos + 1] | (raw[pos + 2] << 8), pos + 3
    if v == 0xFE:
        return (raw[pos + 1] | (raw[pos + 2] << 8) |
                (raw[pos + 3] << 16) | (raw[pos + 4] << 24)), pos + 5
    return 0, pos + 1


def path_from_indices(indices):
    parts = []
    for idx in indices:
        hardened = bool(idx & 0x80000000)
        parts.append(str(idx & 0x7FFFFFFF) + ("'" if hardened else ""))
    return "m/" + "/".join(parts)


def parse_derivation_value(val):
    if len(val) >= 5 and val[4] <= 10 and len(val) == 5 + val[4] * 4:
        indices = [struct.unpack("<I", val[5 + i * 4:9 + i * 4])[0]
                   for i in range(val[4])]
    elif len(val) >= 4 and (len(val) - 4) % 4 == 0:
        indices = [struct.unpack("<I", val[4 + i * 4:8 + i * 4])[0]
                   for i in range((len(val) - 4) // 4)]
    else:
        return None
    return path_from_indices(indices)


def extract_input_paths(psbt_path):
    with open(psbt_path, "rb") as f:
        raw = f.read()

    pos = 5
    while pos < len(raw) and raw[pos] != 0x00:
        klen, pos = read_varint(raw, pos)
        pos += klen
        vlen, pos = read_varint(raw, pos)
        pos += vlen
    pos += 1

    paths = []
    while pos < len(raw):
        if raw[pos] == 0x00:
            pos += 1
            if paths and len(paths[-1]) > 0:
                paths.append([])
            elif not paths:
                paths.append([])
            continue
        klen, pos = read_varint(raw, pos)
        key_type = raw[pos]
        pos += klen
        vlen, pos = read_varint(raw, pos)
        val = raw[pos:pos + vlen]
        pos += vlen

        if not paths:
            paths.append([])
        if key_type == 0x06 and len(val) >= 8:
            p = parse_derivation_value(val)
            if p:
                paths[-1].append(p)
        elif key_type == 0x16 and len(val) >= 5:
            off = 1 + val[0] * 32
            path_bytes = val[off + 4:]
            if len(path_bytes) % 4 == 0:
                indices = [struct.unpack("<I", path_bytes[i:i + 4])[0]
                           for i in range(0, len(path_bytes), 4)]
                paths[-1].append(path_from_indices(indices))

    cleaned = []
    for group in paths:
        if group:
            cleaned.append(group[0])
    return cleaned


def get_unsigned_tx(raw):
    pos = 5
    while pos < len(raw) and raw[pos] != 0x00:
        klen, pos = read_varint(raw, pos)
        kt = raw[pos]
        pos += klen
        vlen, pos = read_varint(raw, pos)
        if kt == 0x00:
            return raw[pos:pos + vlen]
        pos += vlen
    return None


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def bip143_sighash(unsigned_raw, input_idx):
    tx = get_unsigned_tx(unsigned_raw)
    p = 0
    ver = struct.unpack("<I", tx[p:p + 4])[0]
    p += 4
    n_in, p = read_varint(tx, p)
    inputs = []
    for _ in range(n_in):
        prev = tx[p:p + 32]
        p += 32
        vout = struct.unpack("<I", tx[p:p + 4])[0]
        p += 4
        slen, p = read_varint(tx, p)
        p += slen
        seq = struct.unpack("<I", tx[p:p + 4])[0]
        p += 4
        inputs.append((prev, vout, seq))

    n_out, p = read_varint(tx, p)
    outputs = []
    for _ in range(n_out):
        amt = struct.unpack("<q", tx[p:p + 8])[0]
        p += 8
        slen, p = read_varint(tx, p)
        script = tx[p:p + slen]
        p += slen
        outputs.append((amt, script))
    locktime = struct.unpack("<I", tx[p:p + 4])[0]

    pos = 5
    while unsigned_raw[pos] != 0:
        klen, pos = read_varint(unsigned_raw, pos)
        pos += klen
        vlen, pos = read_varint(unsigned_raw, pos)
        pos += vlen
    pos += 1
    for i in range(input_idx + 1):
        amt = None
        spk = None
        while unsigned_raw[pos] != 0:
            klen, pos = read_varint(unsigned_raw, pos)
            kt = unsigned_raw[pos]
            pos += klen
            vlen, pos = read_varint(unsigned_raw, pos)
            val = unsigned_raw[pos:pos + vlen]
            pos += vlen
            if i == input_idx and kt == 0x01:
                amt = struct.unpack("<q", val[:8])[0]
                sl = val[8]
                spk = val[9:9 + sl]
        pos += 1

    hp = sha256d(b"".join(i[0] + struct.pack("<I", i[1]) for i in inputs))
    hs = sha256d(b"".join(struct.pack("<I", i[2]) for i in inputs))
    ho = sha256d(b"".join(struct.pack("<q", a) + bytes([len(s)]) + s
                           for a, s in outputs))
    prev, vout, seq = inputs[input_idx]
    h = spk[2:22]
    scriptcode = bytes([0x19, 0x76, 0xa9, 0x14]) + h + bytes([0x88, 0xac])
    preimage = (struct.pack("<I", ver) + hp + hs + prev + struct.pack("<I", vout) +
                scriptcode + struct.pack("<q", amt) + struct.pack("<I", seq) +
                ho + struct.pack("<I", locktime) + struct.pack("<I", 1))
    return sha256d(preimage)


def extract_final_witness(raw, input_idx):
    pos = 5
    while pos < len(raw) and raw[pos] != 0:
        klen, pos = read_varint(raw, pos)
        pos += klen
        vlen, pos = read_varint(raw, pos)
        pos += vlen
    if pos >= len(raw):
        return None
    pos += 1
    for i in range(input_idx + 1):
        wit = None
        while pos < len(raw) and raw[pos] != 0:
            klen, pos = read_varint(raw, pos)
            if pos >= len(raw):
                return None
            kt = raw[pos]
            pos += klen
            vlen, pos = read_varint(raw, pos)
            if pos + vlen > len(raw):
                return None
            val = raw[pos:pos + vlen]
            pos += vlen
            if i == input_idx and kt == 0x08:
                wit = val
        if pos < len(raw):
            pos += 1
        if i == input_idx:
            return wit
    return None


def parse_p2wpkh_witness(wit):
    if not wit or wit[0] != 0x02:
        return None, None
    p = 1
    siglen = wit[p]
    p += 1
    sig = wit[p:p + siglen]
    p += siglen
    pklen = wit[p]
    p += 1
    pk = wit[p:p + pklen]
    return sig, pk


def verify_p2wpkh_inputs(unsigned_raw, signed_raw):
    tx = get_unsigned_tx(unsigned_raw)
    p = 4
    n_in, p = read_varint(tx, p)
    for i in range(n_in):
        wit = extract_final_witness(signed_raw, i)
        if not wit:
            return False, f"input {i} missing final witness"
        sig, pk = parse_p2wpkh_witness(wit)
        if not sig or not pk:
            return False, f"input {i} bad witness stack"
        sighash = bip143_sighash(unsigned_raw, i)
        cmd = [VERIFY_BIN, sighash.hex(), pk.hex(), sig.hex()]
        ret = subprocess.run(cmd, capture_output=True)
        if ret.returncode != 0:
            return False, f"input {i} signature invalid"
    return True, "signatures valid"


passed = 0
failed = 0

for filename in sorted(os.listdir(UNSIGNED_DIR)):
    if not filename.endswith(".psbt"):
        continue

    unsigned = os.path.join(UNSIGNED_DIR, filename)
    ours     = os.path.join(OUTPUT_DIR, filename)
    theirs   = os.path.join(SIGNED_DIR, filename)

    if filename.startswith("v1_p2wpkh"):
        prefix = "v1_p2wpkh"
    elif filename.startswith("v1_p2tr"):
        prefix = "v1_p2tr"
    else:
        continue

    seed_hex = SEEDS[prefix]
    paths = extract_input_paths(unsigned)
    path_str = paths[0] if paths else None
    if path_str is None:
        print(f"FAIL {filename}: no derivation path in PSBT")
        failed += 1
        continue

    env = os.environ.copy()
    env["FKT_NO_CONFIRM"] = "1"
    cmd = [SIGNER_BIN, seed_hex, path_str, unsigned, ours]
    ret = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if ret.returncode != 0:
        err = (ret.stderr or ret.stdout or "").strip()
        print(f"FAIL {filename}: signer error ({err})")
        failed += 1
        continue

    with open(ours, "rb") as f:
        our_data = f.read()
    with open(theirs, "rb") as f:
        their_data = f.read()

    if our_data == their_data:
        print(f"PASS {filename}")
        passed += 1
        continue

    if prefix == "v1_p2wpkh":
        ok, msg = verify_p2wpkh_inputs(open(unsigned, "rb").read(), our_data)
        if ok:
            print(f"PASS {filename} (sig-verify, paths={paths})")
            passed += 1
        else:
            print(f"FAIL {filename}: {msg} (paths={paths})")
            failed += 1
    else:
        print(f"FAIL {filename}: output differs (paths={paths})")
        failed += 1

print(f"\nResults: PASS={passed} FAIL={failed}")