# $Id: Makefile.am 1441 2009-07-30 12:32:04Z jakob $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

LIBHSM = ../../libhsm/src/libhsm.a
LIBKSM = ../ksm/libksm.a
LIBCOMPAT = ${top_builddir}/common/libcompat.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/common \
	-I$(top_builddir)/common \
	-I$(srcdir)/../common \
	-I$(builddir)/../common \
	-I$(srcdir)/../ksm/include \
	-I$(builddir)/../ksm/include \
	-I$(srcdir)/../../libhsm/src \
	-I$(builddir)/../../libhsm/src \
	@XML2_INCLUDES@ \
	@DB_INCLUDES@ \
	@LDNS_INCLUDES@

opendnssecdatadir = $(datadir)/opendnssec

if USE_MYSQL
dist_opendnssecdata_DATA = database_create.mysql
else
dist_opendnssecdata_DATA = database_create.sqlite3
endif

bin_PROGRAMS =	ods-ksmutil
man1_MANS =	ods-ksmutil.1

ods_ksmutil_SOURCES = ksmutil.c
ods_ksmutil_LDADD = $(LIBKSM) $(LIBHSM) $(LIBCOMPAT)
ods_ksmutil_LDADD += @XML2_LIBS@ @DB_LIBS@ @LDNS_LIBS@
