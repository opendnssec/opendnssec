srcdir=@srcdir@
toolsdir=${srcdir}/tools
bindir = @bindir@

CC=@CC@
CFLAGS=@CFLAGS@ -Wall -Werror -I${toolsdir}
LDFLAGS=@LDFLAGS@ @LIBS@
PKCS11_MODULE=@PKCS11_MODULE@
OBJECTS=ldns_pkcs11.o util.o
prefix=@prefix@
INSTALL = $(srcdir)/install-sh 

TOOLS=sorter get_serial nseccer nsec3er signer_pkcs11 create_dnskey_pkcs11 finalizer

all: ${TOOLS}

sorter: ${OBJECTS} ${toolsdir}/src/sorter.c
	${CC} ${CFLAGS} ${LDFLAGS} -o ${toolsdir}/sorter ${OBJECTS} ${toolsdir}/src/sorter.c

get_serial: ${OBJECTS} ${toolsdir}/src/get_serial.c
	${CC} ${CFLAGS} ${LDFLAGS} -o ${toolsdir}/get_serial ${OBJECTS} ${toolsdir}/src/get_serial.c

nseccer: ${OBJECTS} ${toolsdir}/src/nseccer.c
	${CC} ${CFLAGS} ${LDFLAGS} -o ${toolsdir}/nseccer ${OBJECTS} ${toolsdir}/src/nseccer.c

nsec3er: ${OBJECTS} ${toolsdir}/src/nsec3er.c
	${CC} ${CFLAGS} ${LDFLAGS} -o ${toolsdir}/nsec3er ${OBJECTS} ${toolsdir}/src/nsec3er.c

ldns_pkcs11.o: ${toolsdir}/src/ldns_pkcs11.h ${toolsdir}/src/ldns_pkcs11.c
	${CC} ${CFLAGS} -c -o ldns_pkcs11.o ${toolsdir}/src/ldns_pkcs11.c

util.o: ${toolsdir}/src/util.h ${toolsdir}/src/util.c
	${CC} ${CFLAGS} -c -o util.o ${toolsdir}/src/util.c

signer_pkcs11: ${OBJECTS} ${toolsdir}/src/signer_pkcs11.c
	${CC} ${CFLAGS} ${LDFLAGS} -o ${toolsdir}/signer_pkcs11 ${OBJECTS} ${PKCS11_MODULE} ${toolsdir}/src/signer_pkcs11.c

create_dnskey_pkcs11: ldns_pkcs11.o ${toolsdir}/src/create_dnskey_pkcs11.c
	${CC} ${CFLAGS} ${LDFLAGS} -o ${toolsdir}/create_dnskey_pkcs11 ldns_pkcs11.o ${PKCS11_MODULE} ${toolsdir}/src/create_dnskey_pkcs11.c

finalizer: ${OBJECTS} ${toolsdir}/src/finalizer.c
	${CC} ${CFLAGS} ${LDFLAGS} -o ${toolsdir}/finalizer ${OBJECTS} ${toolsdir}/src/finalizer.c

clean:
	rm -rf ${toolsdir}/sorter ${toolsdir}/stripper ${toolsdir}/nseccer \
	${toolsdir}/nsec3er ${toolsdir}/signer ${toolsdir}/signer_pkcs11 \
	${toolsdir}/create_dnskey_pkcs11 ${toolsdir}/get_serial *.o

realclean: clean
	rm -rf Makefile configure config.h config.log config.status autom4te.cache

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(bindir)
	for i in $(TOOLS); do \
		$(INSTALL) -c -m 755 $(toolsdir)/$$i $(DESTDIR)$(bindir)/$$i ; \
	done
