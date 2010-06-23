# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
		-I$(top_builddir)/common \
		-I$(srcdir)/cryptoki_compat \
		@LDNS_INCLUDES@ @XML2_INCLUDES@
AM_CFLAGS =	-std=c99

noinst_LIBRARIES = libhsm.a

libhsm_a_SOURCES = libhsm.c compat/strlcpy.c compat/strlcat.c

bin_PROGRAMS = ods-hsmutil ods-hsmspeed

man1_MANS = ods-hsmutil.1 ods-hsmspeed.1

ods_hsmutil_SOURCES = hsmutil.c hsmtest.c
ods_hsmutil_LDADD = libhsm.a @LDNS_LIBS@ @XML2_LIBS@

ods_hsmspeed_SOURCES = hsmspeed.c
ods_hsmspeed_LDADD = libhsm.a -lpthread @LDNS_LIBS@ @XML2_LIBS@

EXTRA_DIST = $(srcdir)/cryptoki_compat/*.h
EXTRA_DIST += $(srcdir)/compat/*.c $(srcdir)/compat/*.h
