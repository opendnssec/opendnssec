# $Id: Makefile.am 1829 2009-09-18 22:11:48Z jakob $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	-I$(srcdir)/../common \
	-I$(builddir)/../common \
	-I$(srcdir)/../ksm/include \
	-I$(builddir)/../ksm/include \
	@LIBHSM_INCLUDES@ \
	@XML2_INCLUDES@ \
	@DB_INCLUDES@

sbin_PROGRAMS = ods-enforcerd

ods_enforcerd_SOURCES = enforcer.c
ods_enforcerd_LDADD = ../common/libenforcer.a ../ksm/libksm.a
ods_enforcerd_LDADD += @LIBHSM_LIBS@ @XML2_LIBS@ @DB_LIBS@
ods_enforcerd_DEPENDENCIES = @BUILD_LIBHSM@

EXTRA_DIST = $(srcdir)/*.h

../../libhsm/src/libhsm.la:
	(cd ../../libhsm/src; ${MAKE} libhsm.la)
