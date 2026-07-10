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
       fkt_bech32.o \
       fkt_address.o \
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

# Full app minus main — preview/confirm/seed now pull in UI/TTY/QR.
FUZZ_OBJS = $(filter-out main.o,$(OBJS))

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
	./fkt_fuzz -max_len=4096 -runs=50000 corpus/

clean:
	rm -f *.o fktsigner verify_ecdsa fkt_fuzz test_parse psbt_parse_test test_qr test_bip_vectors
# --- Matrix / v0.2 harness (from test-matrix branch) ---
.PHONY: test-sparrow-real test-sparrow-real-list test-sparrow-real-golden test-scriptpath test-scriptpath-ark test-parity-linux

test-sparrow-real-list:
	python3 tests/sparrow_real_list.py --check

test-sparrow-real: fktsigner verify_ecdsa gen-scriptpath-fixtures
	python3 tests/run_sparrow_real_harness.py $(ARGS)

test-sparrow-real-golden: fktsigner verify_ecdsa gen-scriptpath-fixtures
	python3 tests/run_sparrow_real_harness.py --check-golden $(ARGS)

GEN_SP = tests/gen_scriptpath_vector
SP_SEED ?= dc26536673dd2912aae6863d2984566995154dcdd72c003ebf4dc61e7b93e710e9693f23cfc397ca71bc9362cefb95ab52896d0dc68cfae352b6d8dda13aaeaa
SP_DIR = tests/sparrow-real/unsigned
SP_OUT = tests/sparrow-real/fkt-signed

$(GEN_SP): tests/gen_scriptpath_vector.c $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ tests/gen_scriptpath_vector.c fkt_bip32.o fkt_secp256k1.o fkt_sha256.o fkt_sha512.o fkt_hmac.o fkt_hash160.o fkt_ripemd160.o fkt_util.o fkt_error.o fkt_sighash.o fkt_psbt.o fkt_memzero.o $(SECP_LIB)

.PHONY: gen-scriptpath-fixtures
gen-scriptpath-fixtures: $(GEN_SP)
	@mkdir -p $(SP_DIR) $(SP_OUT)
	$(GEN_SP) $(SP_SEED) $(SP_DIR)/p2tr_script_path_synthetic.psbt checksig
	$(GEN_SP) $(SP_SEED) $(SP_DIR)/p2tr_script_path_csv.psbt csv
	$(GEN_SP) $(SP_SEED) $(SP_DIR)/p2tr_script_path_cltv.psbt cltv
	$(GEN_SP) $(SP_SEED) $(SP_DIR)/p2tr_script_path_csv_cltv.psbt csv_cltv
	$(GEN_SP) $(SP_SEED) $(SP_DIR)/p2tr_script_path_reject_noleaf.psbt reject_noleaf

test-scriptpath: fktsigner gen-scriptpath-fixtures
	./fktsigner $(SP_SEED) "m/86'/1'/0'/0/0" $(SP_DIR)/p2tr_script_path_synthetic.psbt $(SP_OUT)/p2tr_script_path_synthetic.psbt
	@echo "PASS test-scriptpath (checksig)"

# Ark-shaped leaves: CSV / CLTV / both + reject no-leaf
test-scriptpath-ark: fktsigner gen-scriptpath-fixtures
	./fktsigner $(SP_SEED) "m/86'/1'/0'/0/0" $(SP_DIR)/p2tr_script_path_csv.psbt $(SP_OUT)/p2tr_script_path_csv.psbt
	./fktsigner $(SP_SEED) "m/86'/1'/0'/0/0" $(SP_DIR)/p2tr_script_path_cltv.psbt $(SP_OUT)/p2tr_script_path_cltv.psbt
	./fktsigner $(SP_SEED) "m/86'/1'/0'/0/0" $(SP_DIR)/p2tr_script_path_csv_cltv.psbt $(SP_OUT)/p2tr_script_path_csv_cltv.psbt
	@# reject: must fail
	@if ./fktsigner $(SP_SEED) "m/86'/1'/0'/0/0" $(SP_DIR)/p2tr_script_path_reject_noleaf.psbt $(SP_OUT)/p2tr_script_path_reject_noleaf.psbt 2>/dev/null; then \
		echo "FAIL: reject_noleaf should not sign"; exit 1; \
	else \
		echo "PASS reject_noleaf (signer aborted as expected)"; \
	fi
	@echo "PASS test-scriptpath-ark"

# Linux pure-CLI (sign --seed --yes) is the same crypto path as TUI (from_words).
test-parity-linux: fktsigner
	python3 tests/run_parity_linux.py

# P2.1 proprietary 0xFC passthrough (Session B)
.PHONY: test-proprietary
test-proprietary: fktsigner
	python3 tests/run_sparrow_real_harness.py --priority high 2>&1 | tee /tmp/fkt-prop-harness.txt
	@grep -q 'p2wpkh_proprietary_passthrough.*PASS.*proprietary passthrough ok' /tmp/fkt-prop-harness.txt
	@echo "PASS test-proprietary"

# Phase 1 Step 2: modular PSBT core — P2WPKH + Taproot keypath + 0xFC + clean build
.PHONY: test-psbt-core
test-psbt-core: fktsigner verify_ecdsa
	@echo "=== test-psbt-core: clean modular path (parse/sign/finalize) ==="
	python3 tests/run_sparrow_real_harness.py --priority high 2>&1 | tee /tmp/fkt-psbt-core.txt
	@grep -q 'p2wpkh_1in_1out.*PASS' /tmp/fkt-psbt-core.txt
	@grep -q 'p2tr_1in_1out.*PASS' /tmp/fkt-psbt-core.txt
	@grep -q 'mixed_p2wpkh_p2tr_2in_2out.*PASS' /tmp/fkt-psbt-core.txt
	@grep -q 'p2wpkh_proprietary_passthrough.*PASS.*proprietary passthrough ok' /tmp/fkt-psbt-core.txt
	@grep -qE 'Results: PASS=[0-9]+ FAIL=0' /tmp/fkt-psbt-core.txt
	@echo "PASS test-psbt-core"

# Phase 1 Step 3: CLI entry (binary/Base64, preview→seed→sign, Base64 out, QR)
.PHONY: test-cli-entry
test-cli-entry: fktsigner
	python3 tests/run_cli_entry.py
	@echo "PASS test-cli-entry"

# Phase 1 Step 4: BIP vectors, multi-input, SP stub, full umbrella
BIP_VEC_OBJS = fkt_bip39.o fkt_bip32.o fkt_pbkdf2.o fkt_sha256.o fkt_sha512.o \
	fkt_hmac.o fkt_hash160.o fkt_ripemd160.o fkt_secp256k1.o fkt_memzero.o \
	fkt_error.o fkt_util.o

test_bip_vectors: tests/test_bip_vectors.c $(BIP_VEC_OBJS) $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ tests/test_bip_vectors.c $(BIP_VEC_OBJS) $(SECP_LIB)

.PHONY: test-bip-vectors
test-bip-vectors: test_bip_vectors
	./test_bip_vectors
	@echo "PASS test-bip-vectors"

.PHONY: test-multi-input
test-multi-input: fktsigner verify_ecdsa gen-scriptpath-fixtures
	python3 tests/run_multi_input_gate.py
	@echo "PASS test-multi-input"

.PHONY: test-silent-payments-stub
test-silent-payments-stub:
	python3 tests/run_silent_payments_stub.py
	@echo "PASS test-silent-payments-stub"

# Full Phase 1 Step 4 suite — all must PASS
.PHONY: test
test: fktsigner verify_ecdsa
	@echo "========================================"
	@echo " FKT Ice Cold full suite (Phase 1 Step 4)"
	@echo "========================================"
	$(MAKE) test-bip-vectors
	$(MAKE) test-cli-entry
	$(MAKE) test-psbt-core
	$(MAKE) test-proprietary
	$(MAKE) test-scriptpath
	$(MAKE) test-scriptpath-ark
	$(MAKE) test-sparrow-real
	$(MAKE) test-multi-input
	$(MAKE) test-parity-linux
	$(MAKE) test-silent-payments-stub
	@echo "========================================"
	@echo " PASS make test (full suite)"
	@echo "========================================"
