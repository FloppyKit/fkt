CC = gcc
SECP_DIR = ../secp256k1-build
CFLAGS = -std=c89 -Wall -Wextra -I. -I$(SECP_DIR)/include -DFKT_LINUX=1 -DENABLE_MODULE_SCHNORRSIG -DENABLE_MODULE_EXTRAKEYS
DEV_HARNESS ?= 1
ifeq ($(DEV_HARNESS),1)
CFLAGS += -DFKT_DEV_HARNESS=1
endif
NO_FINALIZER ?= 0
ifeq ($(NO_FINALIZER),1)
CFLAGS += -DFKT_NO_FINALIZER=1
endif
ifdef WARM
CFLAGS += -DFKT_WARM_WALLET=1
endif
SECP_LIB = $(SECP_DIR)/libsecp256k1.a

BASE_OBJS = main.o \
       fkt_tty.o \
       fkt_screen.o \
       fkt_file.o \
       fkt_pick.o \
       fkt_cam.o \
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
       fkt_confirm.o \
       fkt_finalizer.o \
       fkt_memzero.o \
       fkt_sighash.o \
       fkt_signer.o \
       fkt_qr.o \
       fkt_qr_vga.o \
       fkt_qrgen_wrap.o \
       fkt_qrgen.o

ifeq ($(NO_FINALIZER),1)
OBJS = $(filter-out fkt_finalizer.o,$(BASE_OBJS))
else
OBJS = $(BASE_OBJS)
endif

.PHONY: all warm fktsigner-release fktsigner-dos test-sparrow test-qr test-parse sparrow-base64 clean fuzz fuzz-corpus

all: fktsigner fkt verify_ecdsa

fktsigner-release:
	$(MAKE) clean
	$(MAKE) DEV_HARNESS=0 NO_FINALIZER=1 fktsigner

fktsigner-dos:
	$(MAKE) -f Makefile.dos

warm:
	$(MAKE) WARM=1 fktsigner fkt

fkt: fktsigner
	ln -sf fktsigner fkt

FUZZ_OBJS = fkt_seed.o fkt_bip39.o fkt_error.o fkt_util.o fkt_sha256.o fkt_sha512.o \
            fkt_hmac.o fkt_pbkdf2.o fkt_ripemd160.o fkt_hash160.o fkt_bip32.o \
            fkt_secp256k1.o fkt_psbt.o fkt_preview.o fkt_confirm.o fkt_finalizer.o \
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

PARSE_TEST_OBJS = fkt_psbt.o fkt_error.o fkt_sha256.o fkt_sha512.o fkt_util.o \
                  fkt_memzero.o

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

# Nayuki QR encoder uses C99 (bool); isolated to these translation units.
fkt_qrgen.o: fkt_qrgen.c fkt_qrgen.h
	$(CC) -std=c99 -Wall -Wextra -I. -c -o $@ fkt_qrgen.c

fkt_qrgen_wrap.o: fkt_qrgen_wrap.c fkt_qrgen_wrap.h fkt_qrgen.h
	$(CC) -std=c99 -Wall -Wextra -I. -c -o $@ fkt_qrgen_wrap.c

fkt_qr_vga.o: fkt_qr_vga.c fkt_qr_vga.h fkt_qr.h
	$(CC) -std=c99 -Wall -Wextra -I. -DFKT_QR_VGA_FB -c -o $@ fkt_qr_vga.c

test_qr: tests/test_qr.c fkt_qr.o fkt_qr_vga.o fkt_qrgen_wrap.o fkt_qrgen.o fkt_memzero.o
	$(CC) $(CFLAGS) -o $@ tests/test_qr.c fkt_qr.o fkt_qr_vga.o fkt_qrgen_wrap.o fkt_qrgen.o fkt_memzero.o

test-qr: test_qr
	./test_qr

test_parse: tests/test_parse.c $(PARSE_TEST_OBJS)
	$(CC) $(CFLAGS) -o test_parse tests/test_parse.c $(PARSE_TEST_OBJS)

psbt_parse_test: tests/psbt_parse_test.c $(PARSE_TEST_OBJS)
	$(CC) $(CFLAGS) -o psbt_parse_test tests/psbt_parse_test.c $(PARSE_TEST_OBJS)

test-parse: test_parse psbt_parse_test
	./test_parse
	python3 tests/run_parser_tests.py --binary ./psbt_parse_test

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
	rm -f *.o fktsigner verify_ecdsa fkt_fuzz test_parse psbt_parse_test test_qr