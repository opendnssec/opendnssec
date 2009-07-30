# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	-I$(srcdir)/../common \
	@XML2_INCLUDES@ \
	@LIBHSM_INCLUDES@ \
	@LIBKSM_INCLUDES@

sbin_PROGRAMS = communicated

communicated_SOURCES = communicator.c
communicated_LDADD = ../common/libenforcer.a @XML2_LIBS@ @LIBKSM_LIBS@
communicated_DEPENDENCIES = @BUILD_LIBKSM@

EXTRA_DIST = $(srcdir)/*.h

../../libksm/src/libksm.la:
	(cd ../../libksm/src; ${MAKE} libksm.la)
