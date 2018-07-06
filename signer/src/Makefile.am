.PHONY: analyze
MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

LIBHSM = ${top_builddir}/libhsm/src/lib/libhsm.a
LIBCOMPAT = ${top_builddir}/common/libcompat.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/common \
	-I$(top_builddir)/common \
    -I$(top_srcdir)/libhsm/src/lib \
	@SSL_INCLUDES@ \
	@XML2_INCLUDES@ \
	@LDNS_INCLUDES@

signerdir =     @libdir@/opendnssec/signer

sbin_PROGRAMS = ods-signerd ods-signer
# man8_MANS =     man/ods-signer.8 man/ods-signerd.8

ods_signerd_SOURCES=		ods-signerd.c \
				adapter/adapi.c adapter/adapi.h \
				adapter/adapter.c adapter/adapter.h \
				adapter/addns.c adapter/addns.h \
				adapter/adfile.c adapter/adfile.h \
				adapter/adutil.c adapter/adutil.h \
				daemon/signercommands.c daemon/signercommands.h \
				daemon/dnshandler.c daemon/dnshandler.h \
				daemon/xfrhandler.c daemon/xfrhandler.h \
				daemon/engine.c daemon/engine.h \
				daemon/signertasks.c daemon/signertasks.h \
				parser/addnsparser.c parser/addnsparser.h \
				parser/signconfparser.c parser/signconfparser.h \
				parser/zonelistparser.c parser/zonelistparser.h \
				hsm.c hsm.h \
				signer/denial.h \
				signer/domain.h \
				signer/keys.c signer/keys.h \
				signer/nsec3params.c signer/nsec3params.h \
				signer/signconf.c signer/signconf.h \
				signer/stats.c signer/stats.h \
				signer/tools.c signer/tools.h \
				signer/zone.c signer/zone.h \
				signer/zonelist.c signer/zonelist.h \
				wire/acl.c wire/acl.h \
				wire/axfr.c wire/axfr.h \
				wire/buffer.c wire/buffer.h \
				wire/edns.c wire/edns.h \
				wire/listener.c wire/listener.h \
				wire/netio.c wire/netio.h \
				wire/notify.c wire/notify.h \
				wire/query.c wire/query.h \
				wire/sock.c wire/sock.h \
				wire/tcpset.c wire/tcpset.h \
				wire/tsig.c wire/tsig.h \
				wire/tsig-openssl.c wire/tsig-openssl.h \
				wire/xfrd.c wire/xfrd.h \
				views/recordset.c \
				views/functions.c \
				views/index.c \
				views/iterator.c \
				views/iteratorgeneric.c \
				views/table.c \
				views/views.c \
				views/marshalling.c \
				views/commitlog.c \
				views/httpd.c views/httpd.h \
				views/ringbuf.h \
				views/rpc.c \
				views/zoneoutput.c \
				views/proto.h

analyze:
	cd $(srcdir) ; cppcheck --quiet --enable=unusedFunction \
	  $(ods_signerd_SOURCES)

ods_signerd_LDADD=		$(LIBHSM)
ods_signerd_LDADD+=		$(LIBCOMPAT)
ods_signerd_LDADD+=		@LDNS_LIBS@ @XML2_LIBS@ @PTHREAD_LIBS@ @RT_LIBS@ @SSL_LIBS@ @C_LIBS@

ods_signer_SOURCES=		ods-signer.c

ods_signer_LDADD=		$(LIBHSM)
ods_signer_LDADD+=		$(LIBCOMPAT)
ods_signer_LDADD+=		@LDNS_LIBS@ @XML2_LIBS@ @READLINE_LIBS@
