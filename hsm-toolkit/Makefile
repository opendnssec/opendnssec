# $Id$

TARGET = hsm-toolkit

CC = gcc

CFLAGS = -O3 -W -Wall -Werror -g -I/usr/include/security
LDFLAGS = -L/usr/local/lib/
LIBS = -lsofthsm

all: $(TARGET)

hsm-toolkit: hsm-toolkit.c
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(LIBS) $@.c

clean:
	rm -f $(TARGET)
