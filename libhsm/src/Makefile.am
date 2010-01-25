# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS =	-I$(srcdir)/.. \
		-I$(srcdir)/cryptoki_compat \
		@LDNS_INCLUDES@ @XML2_INCLUDES@
AM_CFLAGS =	-std=c99

lib_LTLIBRARIES = libhsm.la
libhsm_la_SOURCES = libhsm.c compat/strlcpy.c compat/strlcat.c
libhsm_la_LDFLAGS = -dl -version-info @LIBTOOL_VERSION_INFO@
libhsm_la_LIBADD = @LDNS_LIBS@ @XML2_LIBS@
nobase_include_HEADERS = $(srcdir)/*.h

bin_PROGRAMS = ods-hsmutil ods-hsmspeed

ods_hsmutil_SOURCES = hsmutil.c hsmtest.c
ods_hsmutil_LDADD = libhsm.la

ods_hsmspeed_SOURCES = hsmspeed.c
ods_hsmspeed_LDADD = libhsm.la -lpthread

EXTRA_DIST = $(srcdir)/cryptoki_compat/*.h
EXTRA_DIST += $(srcdir)/compat/*.c $(srcdir)/compat/*.h
