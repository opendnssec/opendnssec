# $Id$

TARGET = hsm-speed

CC = gcc

CFLAGS = -m64 -O3 -W -Wall -Werror -g -I/usr/include/security
LDFLAGS = -L/usr/lib/sparcv9
LIBS = -lpkcs11

all: $(TARGET)

hsm-speed: hsm-speed.c
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(LIBS) $@.c

clean:
	rm -f $(TARGET)
