MAINTAINERCLEANFILES = $(srcdir)/Makefile.in ${srcdir)/conf.xml $(srcdir)/setup.sh

LIBHSM = ${top_builddir}/libhsm/src/lib/libhsm.a
LIBCOMPAT = ${top_builddir}/common/libcompat.a

AM_CPPFLAGS = \
	@PTHREAD_LIBS@ \
	@RT_LIBS@ \
	-I$(top_srcdir)/signer/src \
	-I$(top_srcdir)/libhsm/src/lib \
	-I$(top_srcdir)/common \
	-I$(top_builddir)/common \
	@CUNIT_INCLUDES@ \
	@XML2_INCLUDES@

check_PROGRAMS = signertest

#signertest_SOURCES = signertest.c ../../../contrib/testing-tools/nulllibrary.c
signertest_SOURCES = signertest.c comparezone.c
signertest_LDFLAGS = -rdynamic
signertest_LDADD = \
	../adapter/adapi.o \
	../adapter/adapter.o \
	../adapter/addns.o \
	../adapter/adfile.o \
	../adapter/adutil.o \
	../daemon/signercommands.o \
	../daemon/dnshandler.o \
	../daemon/xfrhandler.o \
	../daemon/engine.o \
	../daemon/signertasks.o \
	../daemon/metastorage.o \
	../parser/addnsparser.o \
	../parser/signconfparser.o \
	../parser/zonelistparser.o \
	../hsm.o \
	../signer/keys.o \
	../signer/nsec3params.o \
	../signer/signconf.o \
	../signer/stats.o \
	../signer/tools.o \
	../signer/zone.o \
	../signer/zonelist.o \
	../wire/acl.o \
	../wire/axfr.o \
	../wire/buffer.o \
	../wire/edns.o \
	../wire/listener.o \
	../wire/netio.o \
	../wire/notify.o \
	../wire/query.o \
	../wire/sock.o \
	../wire/tcpset.o \
	../wire/tsig.o \
	../wire/tsig-openssl.o \
	../wire/xfrd.o \
	../views/commitlog.o \
	../views/recordset.o \
	../daemon/signeroperation.o \
	../views/httpd.o \
	../views/index.o \
	../views/iterator.o \
	../views/iteratorgeneric.o \
	../views/marshalling.o \
	../views/rpc.o \
	../views/table.o \
	../views/views.o \
	../views/zoneoutput.o \
	../views/periodic.o \
	$(LIBHSM) $(LIBCOMPAT) \
	@LDNS_LIBS@ @XML2_LIBS@ @PTHREAD_LIBS@ @RT_LIBS@ @SSL_LIBS@ @C_LIBS@ \
	@CUNIT_LIBS@

check: signertest
	sh setup.sh
	./signertest $(top_srcdir)/signer/src/test
