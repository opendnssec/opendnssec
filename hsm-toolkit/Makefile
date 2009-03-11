# $Id$

TARGET = hsm-toolkit

CC = gcc

CFLAGS = -O3 -W -Wall -Werror -g -I.
LDFLAGS = -L/usr/local/lib/

all: $(TARGET)

hsm-toolkit: hsm-toolkit.c
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $@.c

clean:
	rm -f $(TARGET)
