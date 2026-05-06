CC       = gcc
CFLAGS   = -std=c89 -Wall -O2 -I. -Isecp256k1/include
LDFLAGS  = -Lsecp256k1/.libs -lsecp256k1 -lm
TARGET   = fktsigner
SRCS     = main.c fkt_psbt.c fkt_crypto.c

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

test: $(SRCS)
	$(CC) $(CFLAGS) test_vectors.c fkt_psbt.c fkt_crypto.c -o test_vectors $(LDFLAGS)
	./test_vectors

clean:
	rm -f $(TARGET) test_vectors signed*.psbt
