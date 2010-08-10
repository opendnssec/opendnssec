# $Id$

AM_CPPFLAGS = @LIBHSM_INCLUDES@ @LDNS_INCLUDES@ @XML2_INCLUDES@

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in

opendnsseclibexecdir = $(libexecdir)/opendnssec

opendnsseclibexec_PROGRAMS= \
	get_serial get_class \
	zone_fetcher zone_reader \
	signer create_dnskey \
	finalizer quicksorter

quicksorter_CFLAGS=		-std=gnu99 -funsigned-char
quicksorter_SOURCES=		quicksorter_encode.c
quicksorter_LDADD=		quicksorter.o

# hack to compile quicksorter without optimization
QUICKSORTER_O = quicksorter.o
$(QUICKSORTER_O): quicksorter.c
	$(MAKE) quicksorter.o \
		CFLAGS="$(CFLAGS) -Os $(quicksorter_CFLAGS)" \
		QUICKSORTER_O=

zone_reader_SOURCES=		new_reader.c util.c v2/adapter.c v2/confparser.c v2/duration.c v2/se_key.c v2/signconf.c v2/zone.c v2/adapter.h v2/confparser.h v2/duration.h v2/se_key.h v2/signconf.h v2/zonedata.c v2/adfile.c v2/domain.c v2/nsec3params.c v2/se_malloc.c v2/signconfparser.c v2/zonedata.h v2/adfile.h v2/domain.h v2/nsec3params.h v2/se_malloc.h v2/signconfparser.h v2/zone.h v2/rrset.c v2/rrset.h v2/hsm.c v2/hsm.h
zone_reader_LDADD=		@LDNS_LIBS@ @XML2_LIBS@ @LIBHSM_LIBS@
zone_reader_DEPENDENCIES=	@BUILD_LIBHSM@

zone_fetcher_SOURCES=		zone_fetcher.c util.c logging.c logging.h privdrop.c privdrop.h
zone_fetcher_LDADD=		@LDNS_LIBS@ @XML2_LIBS@

get_class_SOURCES=		get_class.c util.c
get_class_LDADD=		@LDNS_LIBS@

get_serial_SOURCES=		get_serial.c util.c
get_serial_LDADD=		@LDNS_LIBS@

signer_SOURCES=			signer.c util.c logging.c logging.h
signer_LDADD=			@LDNS_LIBS@ @LIBHSM_LIBS@
signer_DEPENDENCIES=		@BUILD_LIBHSM@

create_dnskey_SOURCES=		create_dnskey.c util.c
create_dnskey_LDADD=		@LDNS_LIBS@ @LIBHSM_LIBS@
create_dnskey_DEPENDENCIES=	@BUILD_LIBHSM@

finalizer_SOURCES=		finalizer.c util.c
finalizer_LDADD=		@LDNS_LIBS@

EXTRA_DIST =	$(srcdir)/privdrop.h \
		$(srcdir)/logging.h \
		$(srcdir)/util.h \
		$(srcdir)/quicksorter_encode.h \
		$(srcdir)/zone_fetcher.h \
		$(srcdir)/quicksorter.c

../../libhsm/src/libhsm.la:
	(cd ../../libhsm/src; ${MAKE} libhsm.la)
