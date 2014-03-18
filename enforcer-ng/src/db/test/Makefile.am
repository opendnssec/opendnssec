MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	-I$(top_srcdir)/common \
	-I$(top_builddir)/common \
	@ENFORCER_DB_INCLUDES@ \
	@CUNIT_INCLUDES@

check_PROGRAMS = test

test_SOURCES = test.c

test_LDADD =

test_LDFLAGS = -no-install @CUNIT_LIBS@ @ENFORCER_DB_LIBS@

check: regress-db

regress-db: test
	./test
