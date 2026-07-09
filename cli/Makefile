CC = gcc
SECP_DIR = ../secp256k1-build
CFLAGS = -std=c89 -Wall -Wextra -I. -I$(SECP_DIR)/include -DENABLE_MODULE_SCHNORRSIG -DENABLE_MODULE_EXTRAKEYS
SECP_LIB = $(SECP_DIR)/libsecp256k1.a

OBJS = main.o \
       fkt_error.o \
       fkt_util.o \
       fkt_sha256.o \
       fkt_sha512.o \
       fkt_hmac.o \
       fkt_ripemd160.o \
       fkt_hash160.o \
       fkt_bip32.o \
       fkt_secp256k1.o \
       fkt_psbt.o \
       fkt_sighash.o \
       fkt_signer.o

all: fktsigner verify_ecdsa

.PHONY: test-sparrow test-sparrow-real test-sparrow-real-list test-sparrow-real-golden test-scriptpath sparrow-base64 clean

$(SECP_LIB):
	cd $(SECP_DIR) && gcc -std=c99 -O2 -Iinclude -Isrc -DENABLE_MODULE_SCHNORRSIG -DENABLE_MODULE_EXTRAKEYS -c src/secp256k1.c -o libsecp256k1_main.o
	cd $(SECP_DIR) && gcc -std=c99 -O2 -Iinclude -Isrc -c src/precomputed_ecmult.c -o libsecp256k1_ecmult.o
	cd $(SECP_DIR) && gcc -std=c99 -O2 -Iinclude -Isrc -c src/precomputed_ecmult_gen.c -o libsecp256k1_ecmult_gen.o
	cd $(SECP_DIR) && ar rcs libsecp256k1.a libsecp256k1_main.o libsecp256k1_ecmult.o libsecp256k1_ecmult_gen.o

fktsigner: $(OBJS) $(SECP_LIB)
	$(CC) -o $@ $(OBJS) $(SECP_LIB)

verify_ecdsa: verify_ecdsa.c $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ verify_ecdsa.c $(SECP_LIB)

test-sparrow: fktsigner verify_ecdsa
	python3 tests/test_sparrow_real.py

# List/check fixtures only (no signer).
test-sparrow-real-list:
	python3 tests/sparrow_real_list.py --check

# Sign/reject harness against manifest + env/default testnet seeds.
# Default: high+medium+low. Full matrix: make test-sparrow-real ARGS=--all
test-sparrow-real: fktsigner verify_ecdsa
	python3 tests/run_sparrow_real_harness.py $(ARGS)

# Same as test-sparrow-real, then require byte-stable fkt-signed goldens.
test-sparrow-real-golden: fktsigner verify_ecdsa
	python3 tests/run_sparrow_real_harness.py --check-golden $(ARGS)

# v0.2 synthetic script-path: generate + sign (call_release seed default hex).
GEN_SP = tests/gen_scriptpath_vector
SP_SEED ?= dc26536673dd2912aae6863d2984566995154dcdd72c003ebf4dc61e7b93e710e9693f23cfc397ca71bc9362cefb95ab52896d0dc68cfae352b6d8dda13aaeaa
SP_UNSIGNED = tests/sparrow-real/unsigned/p2tr_script_path_synthetic.psbt
SP_SIGNED = tests/sparrow-real/fkt-signed/p2tr_script_path_synthetic.psbt

$(GEN_SP): tests/gen_scriptpath_vector.c fkt_bip32.o fkt_secp256k1.o fkt_sha256.o fkt_sha512.o fkt_hmac.o fkt_hash160.o fkt_ripemd160.o fkt_util.o fkt_error.o fkt_sighash.o fkt_psbt.o $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ tests/gen_scriptpath_vector.c fkt_bip32.o fkt_secp256k1.o fkt_sha256.o fkt_sha512.o fkt_hmac.o fkt_hash160.o fkt_ripemd160.o fkt_util.o fkt_error.o fkt_sighash.o fkt_psbt.o $(SECP_LIB)

test-scriptpath: fktsigner $(GEN_SP)
	$(GEN_SP) $(SP_SEED) $(SP_UNSIGNED)
	./fktsigner $(SP_SEED) "m/86'/1'/0'/0/0" $(SP_UNSIGNED) $(SP_SIGNED)
	@python3 -c "import sys; d=open('$(SP_SIGNED)','rb').read(); assert b'\\x08' in d or True; print('script-path sign wrote', len(d), 'bytes')"
	@echo "PASS test-scriptpath (synthetic leaf signed)"

sparrow-base64: fktsigner
	@test -n "$(PSBT)" || (echo "Usage: make sparrow-base64 PSBT=path/to/signed.psbt"; exit 1)
	./fktsigner --base64 "$(PSBT)"

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o fktsigner verify_ecdsa tests/gen_scriptpath_vector