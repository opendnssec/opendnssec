# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = -I$(srcdir)/../common @XML2_INCLUDES@ @LIBKSM_INCLUDES@

sbin_PROGRAMS = keygend

keygend_SOURCES = keygend.c
keygend_LDADD = ../common/libenforcer.a @XML2_LIBS@ @LIBKSM_LIBS@

EXTRA_DIST = $(srcdir)/*.h
