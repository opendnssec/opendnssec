# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	-I$(srcdir)/../common \
	-I$(srcdir)/../ksm/include \
	@LIBHSM_INCLUDES@ \
	@XML2_INCLUDES@

sbin_PROGRAMS = keygend

keygend_SOURCES = keygend.c
keygend_LDADD = ../common/libenforcer.a ../ksm/libksm.a
keygend_LDADD += @XML2_LIBS@ @SQLITE3_LIBS@ @LIBHSM_LIBS@
keygend_DEPENDENCIES = @BUILD_LIBHSM@

../../libhsm/src/libhsm.la:
	(cd ../../libhsm/src; ${MAKE} libhsm.la)
