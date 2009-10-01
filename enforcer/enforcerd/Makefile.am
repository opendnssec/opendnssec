# $Id: Makefile.am 1829 2009-09-18 22:11:48Z jakob $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	-I$(srcdir)/../common \
	-I$(builddir)/../common \
	-I$(srcdir)/../ksm/include \
	-I$(builddir)/../ksm/include \
	@XML2_INCLUDES@ \
	@DB_INCLUDES@

sbin_PROGRAMS = enforcerd

enforcerd_SOURCES = enforcer.c
enforcerd_LDADD = ../common/libenforcer.a ../ksm/libksm.a
enforcerd_LDADD += @XML2_LIBS@ @DB_LIBS@

EXTRA_DIST = $(srcdir)/*.h
