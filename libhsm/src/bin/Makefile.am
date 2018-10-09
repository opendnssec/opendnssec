MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

LIBCOMPAT = ${top_builddir}/common/libcompat.a

AM_CPPFLAGS = \
		-I$(top_srcdir)/common \
		-I$(top_builddir)/common \
		-I$(srcdir)/../lib \
		@LDNS_INCLUDES@ @XML2_INCLUDES@

AM_CFLAGS =	-std=c99

bin_PROGRAMS = ods-hsmutil ods-hsmspeed

man1_MANS = ods-hsmutil.1 ods-hsmspeed.1

ods_hsmutil_SOURCES = hsmutil.c hsmtest.c hsmtest.h
ods_hsmutil_LDADD = ../lib/libhsm.a $(LIBCOMPAT) @LDNS_LIBS@ @XML2_LIBS@

ods_hsmspeed_SOURCES = hsmspeed.c
ods_hsmspeed_LDADD = ../lib/libhsm.a $(LIBCOMPAT) -lpthread @LDNS_LIBS@ @XML2_LIBS@
