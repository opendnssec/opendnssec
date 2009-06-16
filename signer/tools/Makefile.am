# $Id$

AM_CPPFLAGS = @LIBHSM_INCLUDES@ @LDNS_INCLUDES@

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in

opendnsseclibexec_PROGRAMS= \
	zone_reader get_serial \
	nseccer nsec3er \
	signer create_dnskey \
	finalizer

zone_reader_SOURCES=		zone_reader.c util.c
zone_reader_LDADD=		@LDNS_LIBS@
get_serial_SOURCES=		get_serial.c util.c
get_serial_LDADD=		@LDNS_LIBS@
nseccer_SOURCES=		nseccer.c util.c
nseccer_LDADD=			@LDNS_LIBS@ @LIBHSM_LIBS@
nsec3er_SOURCES=		nsec3er.c util.c
nsec3er_LDADD=			@LDNS_LIBS@ @LIBHSM_LIBS@
signer_SOURCES=			signer.c util.c
signer_LDADD=			@LDNS_LIBS@ @LIBHSM_LIBS@
create_dnskey_SOURCES=		create_dnskey.c util.c
create_dnskey_LDADD=		@LDNS_LIBS@ @LIBHSM_LIBS@
finalizer_SOURCES=		finalizer.c util.c
finalizer_LDADD=		@LDNS_LIBS@
