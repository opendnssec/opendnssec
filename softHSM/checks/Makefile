# $Id$

TARGET = checks

CC = gcc

CFLAGS = -O3 -W -Wall -Werror -g -I. -I../src/lib/
LDFLAGS = -L/usr/local/lib/
LIBS = -lsofthsm
	
all: $(TARGET)

checks: checks.c
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(LIBS) $@.c

clean:
	rm -f $(TARGET)

