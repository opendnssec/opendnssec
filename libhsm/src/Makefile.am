# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
		-I$(top_srcdir)/common \
		-I$(top_builddir)/common \
		-I$(srcdir)/cryptoki_compat \
		@LDNS_INCLUDES@ @XML2_INCLUDES@

AM_CFLAGS =	-std=c99

noinst_LIBRARIES = libhsm.a

libhsm_a_SOURCES = libhsm.c libhsm.h libhsmdns.h \
	cryptoki_compat/pkcs11.h

bin_PROGRAMS = ods-hsmutil ods-hsmspeed

man1_MANS = ods-hsmutil.1 ods-hsmspeed.1

ods_hsmutil_SOURCES = hsmutil.c hsmtest.c hsmtest.h
ods_hsmutil_LDADD = libhsm.a @LDNS_LIBS@ @XML2_LIBS@

ods_hsmspeed_SOURCES = hsmspeed.c
ods_hsmspeed_LDADD = libhsm.a -lpthread @LDNS_LIBS@ @XML2_LIBS@
