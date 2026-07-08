# Build libsecp256k1.a for DJGPP DOS (small ecmult tables)
SECP_SRC   ?= secp256k1-build
SECP_DIR   ?= secp256k1-build-dos
DJGPP_ROOT ?= $(abspath tools/djgpp)
export LD_LIBRARY_PATH := $(DJGPP_ROOT)/lib/host:$(LD_LIBRARY_PATH)
DOS_CC     ?= $(DJGPP_ROOT)/bin/i586-pc-msdosdjgpp-gcc
DOS_AR     ?= $(DJGPP_ROOT)/bin/i586-pc-msdosdjgpp-ar

SECP_DEFS  = -DECMULT_WINDOW_SIZE=2 -DCOMB_BLOCKS=2 -DCOMB_TEETH=5 \
             -DENABLE_MODULE_SCHNORRSIG -DENABLE_MODULE_EXTRAKEYS
SECP_CFLAGS = -std=c99 -Os -I$(SECP_SRC)/include -I$(SECP_SRC)/src $(SECP_DEFS)

.PHONY: all clean

all: $(SECP_DIR)/libsecp256k1.a

$(SECP_DIR):
	mkdir -p $(SECP_DIR)

$(SECP_DIR)/libsecp256k1.a: | $(SECP_DIR)
	$(DOS_CC) $(SECP_CFLAGS) -c $(SECP_SRC)/src/secp256k1.c \
		-o $(SECP_DIR)/libsecp256k1_main.o
	$(DOS_CC) $(SECP_CFLAGS) -c $(SECP_SRC)/src/precomputed_ecmult.c \
		-o $(SECP_DIR)/libsecp256k1_ecmult.o
	$(DOS_CC) $(SECP_CFLAGS) -c $(SECP_SRC)/src/precomputed_ecmult_gen.c \
		-o $(SECP_DIR)/libsecp256k1_ecmult_gen.o
	cp -r $(SECP_SRC)/include $(SECP_DIR)/
	$(DOS_AR) rcs $@ \
		$(SECP_DIR)/libsecp256k1_main.o \
		$(SECP_DIR)/libsecp256k1_ecmult.o \
		$(SECP_DIR)/libsecp256k1_ecmult_gen.o

clean:
	rm -rf $(SECP_DIR)