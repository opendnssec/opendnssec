# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	-I$(srcdir)/../common \
	-I$(builddir)/../common \
	-I$(srcdir)/../ksm/include \
	-I$(builddir)/../ksm/include \
	@XML2_INCLUDES@ \
	@DB_INCLUDES@

sbin_PROGRAMS = communicated

communicated_SOURCES = communicator.c
communicated_LDADD = ../common/libenforcer.a ../ksm/libksm.a
communicated_LDADD += @XML2_LIBS@ @DB_LIBS@
