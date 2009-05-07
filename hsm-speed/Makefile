# $Id$

TARGET = hsm-speed

CC = gcc

CFLAGS = -O3 -W -Wall -Werror -g -I/usr/include/security
LDFLAGS = -L/usr/lib/sparcv9 -L/usr/local/lib -R/usr/local/lib
LIBS = -lsofthsm

all: $(TARGET)

hsm-speed: hsm-speed.c
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(LIBS) $@.c

clean:
	rm -f $(TARGET)
