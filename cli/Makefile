CC = gcc
CFLAGS = -std=c89 -Wall -Wextra -I. -I../secp256k1/include
LDFLAGS = -L../secp256k1/.libs -lsecp256k1

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

fktsigner: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o fktsigner