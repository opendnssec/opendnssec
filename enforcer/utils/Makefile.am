# $Id: Makefile.am 1441 2009-07-30 12:32:04Z jakob $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	-I$(srcdir)/../common \
	-I$(srcdir)/../ksm/include \
	@LIBHSM_INCLUDES@ \
	@XML2_INCLUDES@

dist_opendnssecdata_DATA = database_create.sqlite3

bin_PROGRAMS = ksmutil

ksmutil_LDADD = ../ksm/libksm.a
ksmutil_LDADD += @XML2_LIBS@ @SQLITE3_LIBS@ @LIBHSM_LIBS@
ksmutil_DEPENDENCIES = @BUILD_LIBHSM@

../../libhsm/src/libhsm.la:
	(cd ../../libhsm/src; ${MAKE} libhsm.la)

../ksm/libksm.a:
	(cd ../ksm; ${MAKE} libksm.a)
