CC = gcc
SECP_DIR = ../secp256k1-build
CFLAGS = -std=c89 -Wall -Wextra -I. -I$(SECP_DIR)/include -DENABLE_MODULE_SCHNORRSIG -DENABLE_MODULE_EXTRAKEYS
SECP_LIB = $(SECP_DIR)/libsecp256k1.a

OBJS = main.o \
       fkt_ui.o \
       fkt_seed.o \
       fkt_bip39.o \
       fkt_error.o \
       fkt_util.o \
       fkt_sha256.o \
       fkt_sha512.o \
       fkt_hmac.o \
       fkt_pbkdf2.o \
       fkt_ripemd160.o \
       fkt_hash160.o \
       fkt_bip32.o \
       fkt_secp256k1.o \
       fkt_psbt.o \
       fkt_preview.o \
       fkt_finalizer.o \
       fkt_memzero.o \
       fkt_sighash.o \
       fkt_signer.o

all: fktsigner verify_ecdsa

FUZZ_OBJS = fkt_seed.o fkt_bip39.o fkt_error.o fkt_util.o fkt_sha256.o fkt_sha512.o \
            fkt_hmac.o fkt_pbkdf2.o fkt_ripemd160.o fkt_hash160.o fkt_bip32.o \
            fkt_secp256k1.o fkt_psbt.o fkt_preview.o fkt_finalizer.o \
            fkt_memzero.o fkt_sighash.o fkt_signer.o

FUZZ_CC := $(shell command -v clang 2>/dev/null)
ifneq ($(FUZZ_CC),)
  FUZZ_SAN = -fsanitize=fuzzer,address
  FUZZ_DEFS = -DFKT_LIBFUZZER
else
  FUZZ_CC = $(CC)
  FUZZ_SAN =
  FUZZ_DEFS =
endif

.PHONY: test-sparrow sparrow-base64 clean fuzz fuzz-corpus

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

sparrow-base64: fktsigner
	@test -n "$(PSBT)" || (echo "Usage: make sparrow-base64 PSBT=path/to/signed.psbt"; exit 1)
	./fktsigner --base64 "$(PSBT)"

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

fkt_fuzz: fkt_fuzz.c $(FUZZ_OBJS) $(SECP_LIB)
	$(FUZZ_CC) -std=c89 -Wall -Wextra -g $(FUZZ_DEFS) $(FUZZ_SAN) \
		-I. -I$(SECP_DIR)/include \
		-DENABLE_MODULE_SCHNORRSIG -DENABLE_MODULE_EXTRAKEYS \
		-o fkt_fuzz fkt_fuzz.c $(FUZZ_OBJS) $(SECP_LIB)

fuzz-corpus:
	python3 tests/fuzz/seed_corpus.py

fuzz: fkt_fuzz fuzz-corpus
	./fkt_fuzz -max_len=4096 -runs=10000 corpus/

clean:
	rm -f *.o fktsigner verify_ecdsa fkt_fuzz