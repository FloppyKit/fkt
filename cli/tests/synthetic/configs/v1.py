"""V1 test cases – core single‑sig (P2WPKH, P2TR key‑path, P2SH‑P2WPKH)."""

cases = []

def add(name, script, value_in, values_out, num_inputs=1,
        sequence=0xfffffffd, locktime=0, expected="sign",
        tap_internal_key=None, redeem_script=None,
        duplicate_txid=False, sighash=None, unknown_key=None, **kwargs):
    cases.append({
        "name": name,
        "script": script,
        "value_in": value_in,
        "values_out": values_out,
        "num_inputs": num_inputs,
        "sequence": sequence,
        "locktime": locktime,
        "expected": expected,
        "tap_internal_key": tap_internal_key,
        "redeem_script": redeem_script,
        "duplicate_txid": duplicate_txid,
        "sighash": sighash,
        "unknown_key": unknown_key,
    })

# ---- P2WPKH ----
add("p2wpkh_1in_1out",             "p2wpkh", 100000, [90000])
add("p2wpkh_1in_2out",             "p2wpkh", 200000, [100000, 90000])
add("p2wpkh_2in_2out",             "p2wpkh", 200000, [100000, 90000], num_inputs=2)
add("p2wpkh_3in_2out",             "p2wpkh", 300000, [150000, 140000], num_inputs=3)
add("p2wpkh_rbf",                  "p2wpkh", 100000, [90000], sequence=0xfffffffd)
add("p2wpkh_final_seq",            "p2wpkh", 100000, [90000], sequence=0xffffffff)
add("p2wpkh_locktime",             "p2wpkh", 100000, [90000], locktime=100)
add("p2wpkh_high_locktime",        "p2wpkh", 100000, [90000], locktime=700000)
add("p2wpkh_very_high_locktime",   "p2wpkh", 100000, [90000], locktime=0xFFFFFFFF)
add("p2wpkh_dust",                 "p2wpkh", 546, [536])
add("p2wpkh_dust_1in_1out",        "p2wpkh", 546, [536])
add("p2wpkh_consolidate",          "p2wpkh", 300000, [290000], num_inputs=3)
add("p2wpkh_minimal_fee",          "p2wpkh", 100000, [99900])
add("p2wpkh_max_sequence",         "p2wpkh", 100000, [90000], sequence=0xffffffff)

# ---- P2TR key‑path ----
add("p2tr_1in_1out",     "p2tr", 100000, [90000])
add("p2tr_2in_2out",     "p2tr", 200000, [100000, 90000], num_inputs=2)
add("p2tr_locktime",     "p2tr", 100000, [90000], locktime=500000)
add("p2tr_rbf",          "p2tr", 100000, [90000], sequence=0xfffffffd)
add("p2tr_dust",         "p2tr", 546, [536])

# ---- P2SH‑P2WPKH ----
add("p2sh_p2wpkh_1in_1out", "p2sh_p2wpkh", 100000, [90000])

# ---- Rejection cases ----
add("duplicate_outpoint", "p2wpkh", 200000, [190000], num_inputs=2,
    expected="reject", duplicate_txid=True)
add("p2wpkh_single",       "p2wpkh", 100000, [90000, 10000],
    expected="reject", sighash=0x03)
add("p2wpkh_none",         "p2wpkh", 100000, [90000, 10000],
    expected="reject", sighash=0x02)
add("p2wpkh_acp",          "p2wpkh", 100000, [90000, 10000],
    expected="reject", sighash=0x81)
add("unknown_key", "p2wpkh", 100000, [90000], expected="reject", unknown_key=0x99)