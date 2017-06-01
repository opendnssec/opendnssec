MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

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

check_PROGRAMS = test

test_SOURCES = signertest.c ../../../contrib/testing-tools/nulllibrary.c

test_LDFLAGS = -rdynamic
test_LDADD = \
	../adapter/adapi.o \
	../adapter/adapter.o \
	../adapter/addns.o \
	../adapter/adfile.o \
	../adapter/adutil.o \
	../daemon/cfg.o \
	../daemon/signercommands.o \
	../daemon/dnshandler.o \
	../daemon/xfrhandler.o \
	../daemon/engine.o \
	../daemon/signertasks.o \
	../parser/addnsparser.o \
	../parser/confparser.o \
	../parser/signconfparser.o \
	../parser/zonelistparser.o \
	../signer/backup.o \
	../hsm.o \
	../signer/denial.o \
	../signer/domain.o \
	../signer/ixfr.o \
	../signer/keys.o \
	../signer/namedb.o \
	../signer/names.o \
	../signer/nsec3params.o \
	../signer/rrset.o \
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
	$(LIBHSM) $(LIBCOMPAT) \
	@LDNS_LIBS@ @XML2_LIBS@ @PTHREAD_LIBS@ @RT_LIBS@ @SSL_LIBS@ @C_LIBS@ \
	@CUNIT_LIBS@

check: test
	./test $(top_srcdir)/signer/src/test
