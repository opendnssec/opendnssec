# $Id$

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in

opendnsseclibexec_PROGRAMS= \
	zone_reader get_serial \
	nseccer nsec3er \
	signer create_dnskey \
	finalizer

zone_reader_SOURCES=	zone_reader.c util.c
get_serial_SOURCES=		get_serial.c util.c
nseccer_SOURCES=		nseccer.c util.c
nsec3er_SOURCES=		nsec3er.c util.c
signer_SOURCES=			signer.c util.c
signer_LDFLAGS=			@XML_LIBS@
create_dnskey_SOURCES=	create_dnskey.c util.c
create_dnskey_LDFLAGS=	@XML_LIBS@
finalizer_SOURCES=		finalizer.c util.c
