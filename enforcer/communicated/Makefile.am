# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	-I$(srcdir)/../common \
	-I$(srcdir)/../ksm/include \
	@LIBHSM_INCLUDES@ \
	@XML2_INCLUDES@

sbin_PROGRAMS = communicated

communicated_SOURCES = communicator.c
communicated_LDADD = ../common/libenforcer.a ../ksm/libksm.a
communicated_LDADD += @XML2_LIBS@ @SQLITE3_LIBS@ @LIBHSM_LIBS@
