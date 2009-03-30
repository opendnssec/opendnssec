# $Id$

TARGET = hsm-toolkit

CC = gcc

CFLAGS = -O3 -W -Wall -Werror -g -I. -Icryptoki
LIBS = -ldl
OBJS = pktools.o

default: $(TARGET)

$(TARGET): ${OBJS} hsm-toolkit.c
	$(CC) -o $@ $(CFLAGS) ${OBJS} $(LIBS) $@.c

clean:
	rm -f ${OBJS} $(TARGET)
