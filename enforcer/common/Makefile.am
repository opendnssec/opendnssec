# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	-I$(top_builddir)/common \
	-I$(srcdir)/../ksm/include \
	-I$(builddir)/../ksm/include \
	-I$(srcdir)/../../libhsm/src \
	-I$(builddir)/../../libhsm/src \
	@XML2_INCLUDES@ \
	@DB_INCLUDES@

noinst_LIBRARIES = libenforcer.a

libenforcer_a_SOURCES = daemon.c daemon.h \
	daemon_util.c daemon_util.h \
	kaspaccess.c kaspaccess.h \
	privdrop.c privdrop.h
