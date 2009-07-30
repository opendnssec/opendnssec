# $Id$

AM_CPPFLAGS = @XML2_INCLUDES@ @LIBHSM_INCLUDES@ @LIBKSM_INCLUDES@

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

noinst_LIBRARIES = libenforcer.a

libenforcer_a_DEPENDENCIES = @BUILD_LIBKSM@
libenforcer_a_SOURCES = daemon.c daemon_util.c kaspaccess.c

EXTRA_DIST = $(srcdir)/*.h

../../libksm/src/libksm.la:
	(cd ../../libksm/src; ${MAKE})
