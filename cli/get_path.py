import struct

with open("tests/sparrow-real/Unsigned/v1/v1_p2wpkh_1in_1out.psbt", "rb") as f:
    data = f.read()

pos = 5   # skip magic

def read_varint():
    global pos
    if pos >= len(data): return None
    first = data[pos]; pos += 1
    if first < 0xFD:
        return first
    elif first == 0xFD:
        if pos+2 > len(data): return None
        val = struct.unpack("<H", data[pos:pos+2])[0]; pos += 2
        return val
    elif first == 0xFE:
        if pos+4 > len(data): return None
        val = struct.unpack("<I", data[pos:pos+4])[0]; pos += 4
        return val
    else:
        if pos+8 > len(data): return None
        val = struct.unpack("<Q", data[pos:pos+8])[0]; pos += 8
        return val

# skip global map
while True:
    key_len = read_varint()
    if key_len is None or key_len == 0:
        break
    pos += key_len
    val_len = read_varint()
    if val_len is None:
        break
    pos += val_len

# first input map – find key 0x06
while True:
    key_len = read_varint()
    if key_len is None or key_len == 0:
        break
    key_type = data[pos]; pos += 1
    if key_len > 1:
        pos += key_len - 1
    val_len = read_varint()
    if val_len is None:
        break
    val_start = pos
    pos += val_len
    if key_type == 0x06 and val_len >= 37:
        pub = data[val_start:val_start+33].hex()
        fp  = data[val_start+33:val_start+37].hex()
        path_len = data[val_start+37]
        path = []
        for i in range(path_len):
            idx = struct.unpack("<I", data[val_start+38+i*4:val_start+42+i*4])[0]
            path.append(idx)
        print("pubkey:", pub)
        print("fingerprint:", fp)
        print("path:", [hex(p) for p in path])
        break