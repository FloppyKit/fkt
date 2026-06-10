import struct, hashlib

def p2wpkh_script(pubkey):
    h160 = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
    return b'\x00\x14' + h160

def p2tr_script(pubkey):
    xonly = pubkey[1:]
    return b'\x51\x20' + xonly

def p2sh_p2wpkh_script(pubkey):
    redeem = p2wpkh_script(pubkey)
    h160 = hashlib.new('ripemd160', redeem).digest()
    return b'\xa9\x14' + h160 + b'\x87'

def build_psbt(value_in, values_out, script_pubkey,
               num_inputs=1, sequence=0xfffffffd, locktime=0,
               tap_internal_key=None, redeem_script=None,
               duplicate_txid=False, sighash=None, unknown_key=None):
    per_input = value_in // num_inputs
    tx = b""
    tx += struct.pack("<I", 2)          # version
    tx += bytes([num_inputs])
    first_txid = b'\x00' * 32
    for i in range(num_inputs):
        if not duplicate_txid:
            txid = bytes(31) + bytes([i])
        else:
            txid = first_txid
        tx += txid + struct.pack("<I", 0) + b'\x00' + struct.pack("<I", sequence)
    tx += bytes([len(values_out)])
    for val in values_out:
        tx += struct.pack("<q", val) + bytes([len(script_pubkey)]) + script_pubkey
    tx += struct.pack("<I", locktime)

    psbt = bytes.fromhex("70736274ff")   # magic
    # global map
    psbt += b'\x01\x00'
    utx_len = len(tx)
    if utx_len < 0xFD:
        psbt += bytes([utx_len])
    else:
        psbt += b'\xFD' + struct.pack("<H", utx_len)
    psbt += tx
    psbt += b'\x00'

    # input maps
    for _ in range(num_inputs):
        # witness_utxo (0x01)
        psbt += b'\x01\x01'
        wit = struct.pack("<q", per_input) + bytes([len(script_pubkey)]) + script_pubkey
        wit_len = len(wit)
        if wit_len < 0xFD:
            psbt += bytes([wit_len])
        else:
            psbt += b'\xFD' + struct.pack("<H", wit_len)
        psbt += wit

        if tap_internal_key is not None:
            psbt += b'\x01\x18' + bytes([32]) + tap_internal_key

        if redeem_script is not None:
            psbt += b'\x01\x04' + bytes([len(redeem_script)]) + redeem_script

        if sighash is not None:
            psbt += b'\x01\x03' + bytes([4]) + struct.pack("<I", sighash)

        if unknown_key is not None:
            psbt += b'\x01' + bytes([unknown_key]) + bytes([1]) + b'\x00'

        # input terminator
        psbt += b'\x00'

    # output maps (empty)
    for _ in values_out:
        psbt += b'\x00'

    return psbt