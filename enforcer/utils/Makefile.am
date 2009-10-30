# $Id: Makefile.am 1441 2009-07-30 12:32:04Z jakob $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	-I$(srcdir)/../common \
	-I$(builddir)/../common \
	-I$(srcdir)/../ksm/include \
	-I$(builddir)/../ksm/include \
	@LIBHSM_INCLUDES@ \
	@XML2_INCLUDES@ \
	@DB_INCLUDES@ \
	@LDNS_INCLUDES@

AM_CFLAGS = -std=c99

if MYSQL
dist_opendnssecdata_DATA = database_create.mysql
else
dist_opendnssecdata_DATA = database_create.sqlite3
endif

bin_PROGRAMS = ods-ksmutil

ods_ksmutil_SOURCES = ksmutil.c
ods_ksmutil_LDADD = ../ksm/libksm.a
ods_ksmutil_LDADD += @XML2_LIBS@ @DB_LIBS@ @LIBHSM_LIBS@ @LDNS_LIBS@
ods_ksmutil_DEPENDENCIES = @BUILD_LIBHSM@

../../libhsm/src/libhsm.la:
	(cd ../../libhsm/src; ${MAKE} libhsm.la)

../ksm/libksm.a:
	(cd ../ksm; ${MAKE} libksm.a)

install-data-hook:
	rm -f $(DESTDIR)$(bindir)/ksmutil
	$(LN_S) ods-ksmutil $(DESTDIR)$(bindir)/ksmutil
