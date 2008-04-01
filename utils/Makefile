# $Id$

TARGETS=	getslot

CFLAGS=
LDFLAGS=	-lpkcs11


all: $(TARGETS)

getslot: getslot.c
	$(CC) -c $(CFLAGS) getslot.c
	$(CC) -o $@ $(LDFLAGS) getslot.o

clean:
	rm -f $(TARGETS) *.o
