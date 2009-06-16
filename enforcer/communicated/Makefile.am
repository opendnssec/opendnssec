# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = -I$(srcdir)/../common @XML2_INCLUDES@ @LIBKSM_INCLUDES@

sbin_PROGRAMS = communicated

communicated_SOURCES = communicator.c
communicated_LDADD = ../common/libenforcer.a @XML2_LIBS@ @LIBKSM_LIBS@

EXTRA_DIST = $(srcdir)/*.h
