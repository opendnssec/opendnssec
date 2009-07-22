# $Id: Makefile.am 1019 2009-06-16 13:16:53Z jakob $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS =	-I$(srcdir)/.. \
		-I$(srcdir)/cryptoki \
		@CUNIT_INCLUDES@
AM_CFLAGS =	-std=c99

AM_LDFLAGS =	-rdynamic

bin_PROGRAMS = hsmbully

hsmbully_LDADD = @pkcs11_module@ @CUNIT_LIBS@

EXTRA_DIST = $(srcdir)/cryptoki/*.h
