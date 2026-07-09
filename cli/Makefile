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

.PHONY: test-sparrow test-sparrow-real test-sparrow-real-list test-sparrow-real-golden sparrow-base64 clean

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

sparrow-base64: fktsigner
	@test -n "$(PSBT)" || (echo "Usage: make sparrow-base64 PSBT=path/to/signed.psbt"; exit 1)
	./fktsigner --base64 "$(PSBT)"

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o fktsigner verify_ecdsa