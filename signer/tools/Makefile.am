# $Id$

CC=@CC@
CFLAGS=@CFLAGS@ -Wall -Werror -I. -I${srcdir}
LDFLAGS=@LDFLAGS@ @LIBS@

PKCS11_MODULE=@PKCS11_MODULE@
OBJECTS=${srcdir}/util.o
PKCS11_OBJECTS=${srcdir}/ldns_pkcs11.o

TOOLS=	sorter get_serial nseccer nsec3er \
	signer_pkcs11 create_dnskey_pkcs11 finalizer

all: ${TOOLS}

sorter: ${OBJECTS} ${srcdir}/src/sorter.c
	${CC} ${CFLAGS} ${LDFLAGS} -o sorter ${OBJECTS} ${srcdir}/src/sorter.c

get_serial: ${OBJECTS} ${srcdir}/src/get_serial.c
	${CC} ${CFLAGS} ${LDFLAGS} -o get_serial ${OBJECTS} ${srcdir}/src/get_serial.c

nseccer: ${OBJECTS} ${srcdir}/src/nseccer.c
	${CC} ${CFLAGS} ${LDFLAGS} -o nseccer ${OBJECTS} ${srcdir}/src/nseccer.c

nsec3er: ${OBJECTS} ${srcdir}/src/nsec3er.c
	${CC} ${CFLAGS} ${LDFLAGS} -o nsec3er ${OBJECTS} ${srcdir}/src/nsec3er.c

ldns_pkcs11.o: ${srcdir}/src/ldns_pkcs11.h ${srcdir}/src/ldns_pkcs11.c
	${CC} ${CFLAGS} -c -o ldns_pkcs11.o ${srcdir}/src/ldns_pkcs11.c

util.o: ${srcdir}/src/util.h ${srcdir}/src/util.c
	${CC} ${CFLAGS} -c -o util.o ${srcdir}/src/util.c

signer_pkcs11: ${OBJECTS} ${PKCS11_OBJECTS} ${srcdir}/src/signer_pkcs11.c
	${CC} ${CFLAGS} ${LDFLAGS} -o signer_pkcs11 ${OBJECTS} ${PKCS11_OBJECTS} ${PKCS11_MODULE} ${srcdir}/src/signer_pkcs11.c

create_dnskey_pkcs11: ${PKCS11_OBJECTS} ${srcdir}/src/create_dnskey_pkcs11.c
	${CC} ${CFLAGS} ${LDFLAGS} -o create_dnskey_pkcs11 ldns_pkcs11.o ${PKCS11_OBJECTS} ${PKCS11_MODULE} ${srcdir}/src/create_dnskey_pkcs11.c

finalizer: ${OBJECTS} ${srcdir}/src/finalizer.c
	${CC} ${CFLAGS} ${LDFLAGS} -o finalizer ${OBJECTS} ${srcdir}/src/finalizer.c

clean:
	rm -f sorter stripper nseccer \
	nsec3er signer signer_pkcs11 \
	create_dnskey_pkcs11 get_serial *.o

realclean: clean
	rm -rf Makefile configure config.h config.log config.status autom4te.cache

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(libexecdir)/opendnssec
	for i in $(TOOLS); do \
		$(INSTALL) -c -m 755 $$i $(DESTDIR)$(libexecdir)/opendnssec/$$i ; \
	done
