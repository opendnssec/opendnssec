# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	-I$(srcdir)/../common \
	@XML2_INCLUDES@ \
	@LIBHSM_INCLUDES@ \
	@LIBKSM_INCLUDES@

sbin_PROGRAMS = keygend

keygend_SOURCES = keygend.c
keygend_LDADD = ../common/libenforcer.a @XML2_LIBS@ @LIBKSM_LIBS@
keygend_DEPENDENCIES = @BUILD_LIBHSM@ @BUILD_LIBKSM@

EXTRA_DIST = $(srcdir)/*.h

../../libhsm/src/libhsm.la:
	(cd ../../libhsm/src; ${MAKE} libhsm.la)

../../libksm/src/libksm.la:
	(cd ../../libksm/src; ${MAKE} libksm.la)
