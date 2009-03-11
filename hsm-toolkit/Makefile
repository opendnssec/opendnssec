# $Id$

TARGET = hsm-toolkit

CC = gcc

CFLAGS = -O3 -W -Wall -Werror -g -I.
LIBS = -ldl

all: $(TARGET)

hsm-toolkit: hsm-toolkit.c
	$(CC) -o $@ $(CFLAGS) $(LIBS) $@.c

clean:
	rm -f $(TARGET)
