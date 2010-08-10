# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	-I$(srcdir)/../ksm/include \
	-I$(builddir)/../ksm/include \
	@LIBHSM_INCLUDES@ \
	@XML2_INCLUDES@ \
    @DB_INCLUDES@

noinst_LIBRARIES = libenforcer.a

libenforcer_a_SOURCES = daemon.c daemon_util.c kaspaccess.c privdrop.c

EXTRA_DIST =	$(srcdir)/daemon.h \
		$(srcdir)/daemon_util.h \
		$(srcdir)/kaspaccess.h \
		$(srcdir)/privdrop.h
