# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS =	-I$(srcdir)/.. \
		-I$(srcdir)/cryptoki \
		@LDNS_INCLUDES@ @XML2_INCLUDES@
AM_CFLAGS =	-std=c99

lib_LTLIBRARIES = libhsm.la
libhsm_la_SOURCES = libhsm.c
libhsm_la_LDFLAGS = -dl
libhsm_la_LIBADD = @LDNS_LIBS@ @XML2_LIBS@
nobase_include_HEADERS = $(srcdir)/*.h

bin_PROGRAMS = hsmutil

hsmutil_LDADD = libhsm.la

EXTRA_DIST = $(srcdir)/cryptoki/*.h
