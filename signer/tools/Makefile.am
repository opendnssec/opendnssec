# $Id$

AM_CPPFLAGS = @LIBHSM_INCLUDES@ @LDNS_INCLUDES@ @XML2_INCLUDES@

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in

opendnsseclibexec_PROGRAMS= \
	sorter get_serial \
	zone_fetcher zone_reader \
	nseccer nsec3er \
	signer create_dnskey \
	finalizer signer_threads

sorter_SOURCES=			sorter.c util.c
sorter_LDADD=			@LDNS_LIBS@

zone_reader_SOURCES=		zone_reader.c util.c
zone_reader_LDADD=		@LDNS_LIBS@

zone_fetcher_SOURCES=		zone_fetcher.c util.c logging.c logging.h
zone_fetcher_LDADD=		@LDNS_LIBS@ @XML2_LIBS@

get_serial_SOURCES=		get_serial.c util.c
get_serial_LDADD=		@LDNS_LIBS@

nseccer_SOURCES=		nseccer.c util.c
nseccer_LDADD=			@LDNS_LIBS@ @LIBHSM_LIBS@
nseccer_DEPENDENCIES=		@BUILD_LIBHSM@

nsec3er_SOURCES=		nsec3er.c util.c
nsec3er_LDADD=			@LDNS_LIBS@ @LIBHSM_LIBS@
nsec3er_DEPENDENCIES=		@BUILD_LIBHSM@

signer_SOURCES=			signer.c util.c
signer_LDADD=			@LDNS_LIBS@ @LIBHSM_LIBS@
signer_DEPENDENCIES=		@BUILD_LIBHSM@

signer_threads_SOURCES=		signer_threads.c util.c
signer_threads_LDADD=		@LDNS_LIBS@ @LIBHSM_LIBS@ -lpthread
signer_threads_DEPENDENCIES=	@BUILD_LIBHSM@

create_dnskey_SOURCES=		create_dnskey.c util.c
create_dnskey_LDADD=		@LDNS_LIBS@ @LIBHSM_LIBS@
create_dnskey_DEPENDENCIES=	@BUILD_LIBHSM@

finalizer_SOURCES=		finalizer.c util.c
finalizer_LDADD=		@LDNS_LIBS@

EXTRA_DIST = $(srcdir)/*.h

../../libhsm/src/libhsm.la:
	(cd ../../libhsm/src; ${MAKE} libhsm.la)
