# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

LIBHSM = ${top_builddir}/libhsm/src/libhsm.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/common \
	-I$(top_builddir)/common \
	-I$(srcdir)/../../libhsm/src \
	-I$(builddir)/../../libhsm/src \
	@XML2_INCLUDES@ \
	@LDNS_INCLUDES@

signerdir =     @libdir@/opendnssec/signer

sbin_PROGRAMS = ods-signerd ods-signer
# man8_MANS =     man/ods-signer.8 man/ods-signerd.8

ods_signerd_SOURCES=		ods-signerd.c \
				adapter/adapter.c adapter/adapter.h \
				adapter/adfile.c adapter/adfile.h \
				daemon/cmdhandler.c daemon/cmdhandler.h \
				daemon/cfg.c daemon/cfg.h \
				daemon/engine.c daemon/engine.h \
				daemon/signal.c daemon/signal.h \
				daemon/worker.c daemon/worker.h \
				parser/confparser.c parser/confparser.h \
				parser/signconfparser.c parser/signconfparser.h \
				parser/zonelistparser.c parser/zonelistparser.h \
				scheduler/locks.c scheduler/locks.h \
				scheduler/task.c scheduler/task.h \
				signer/backup.c signer/backup.h \
				signer/domain.c signer/domain.h \
				signer/hsm.c signer/hsm.h \
				signer/nsec3params.c signer/nsec3params.h \
				signer/rrset.c signer/rrset.h \
				signer/se_key.c signer/se_key.h \
				signer/signconf.c signer/signconf.h \
				signer/stats.c signer/stats.h \
				signer/tools.c signer/tools.h \
				signer/zone.c signer/zone.h \
				signer/zonedata.c signer/zonedata.h \
				signer/zonelist.c signer/zonelist.h \
				tools/toolutil.c tools/toolutil.h \
				tools/zone_fetcher.c tools/zone_fetcher.h \
				util/duration.c util/duration.h \
				util/file.c util/file.h \
				util/log.c util/log.h \
				util/privdrop.c util/privdrop.h \
				util/se_malloc.c util/se_malloc.h \
				util/util.c util/util.h

ods_signerd_LDADD=		$(LIBHSM)
ods_signerd_LDADD+=		@LDNS_LIBS@ @XML2_LIBS@ @PTHREAD_LIBS@ @RT_LIBS@

ods_signer_SOURCES=		ods-signer.c \
				util/duration.c util/duration.h \
				util/file.c util/file.h \
				util/log.c util/log.h \
				util/se_malloc.c util/se_malloc.h

ods_signer_LDADD=		$(LIBHSM)
ods_signer_LDADD+=		@LDNS_LIBS@ @XML2_LIBS@
