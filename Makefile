PREFIX ?= /usr/local
CC ?= cc
CFLAGS ?= -O2
CPPFLAGS ?= -D_FILE_OFFSET_BITS=64 -DED25519_REFHASH -DED25519_CUSTOMRANDOM
INCLUDES ?= -Ivendor/ed25519-donna -Icrypto
SRCS = bcp.c crypto/sha256.c vendor/ed25519-donna/ed25519.c

all: bcp

bcp: $(SRCS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INCLUDES) -o bcp $(SRCS)

install: bcp
	cp -f bcp $(PREFIX)/bin/bcp

uninstall:
	rm -f $(PREFIX)/bin/bcp

clean:
	rm -rf bcp.o bcp

.PHONY: install uninstall
