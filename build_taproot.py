import struct

taproot_xonly = bytes.fromhex("2ac617b2c5d5a81c29be9b7bdc4eb449832647bac292b57ed8be1c0921c71d2e")
script = b'\x51\x20' + taproot_xonly
value_in = 100_000
values_out = [90_000]

# unsigned tx
tx = struct.pack("<I", 2)               # version
tx += b"\x01"                           # input count
tx += b"\x00" * 32                      # dummy txid
tx += struct.pack("<I", 0)              # vout
tx += b"\x00"                           # scriptSig len 0
tx += struct.pack("<I", 0xfffffffd)     # sequence
tx += bytes([len(values_out)])
for v in values_out:
    tx += struct.pack("<q", v) + bytes([len(script)]) + script
tx += struct.pack("<I", 0)              # locktime

# PSBT
psbt = bytes.fromhex("70736274ff")      # magic
# global map
psbt += b"\x01\x00"                     # key type 0x00 (unsigned tx)
utx_len = len(tx)
psbt += bytes([utx_len]) if utx_len < 0xFD else b"\xFD" + struct.pack("<H", utx_len)
psbt += tx
psbt += b"\x00"                         # global terminator

# input map
# witness_utxo
wit = struct.pack("<q", value_in) + bytes([len(script)]) + script
psbt += b"\x01\x01"                     # key type 0x01
psbt += bytes([len(wit)]) + wit
# PSBT_IN_TAP_INTERNAL_KEY = 0x18
psbt += b"\x01\x18"                     # key length 1, key type 0x18
psbt += bytes([32]) + taproot_xonly
# input terminator
psbt += b"\x00"

# output map (empty)
psbt += b"\x00"

with open("test_taproot.psbt", "wb") as f:
    f.write(psbt)
print("test_taproot.psbt created")
