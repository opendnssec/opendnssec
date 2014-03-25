MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

LIBHSM = ${top_builddir}/libhsm/src/lib/libhsm.a
LIBKSM = ../ksm/libksm.a
LIBCOMPAT = ${top_builddir}/common/libcompat.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/common \
	-I$(top_builddir)/common \
	-I$(top_srcdir)/libhsm/src/lib \
	-I$(srcdir)/../common \
	-I$(builddir)/../common \
	-I$(srcdir)/../ksm/include \
	-I$(builddir)/../ksm/include \
	@XML2_INCLUDES@ \
	@DB_INCLUDES@ \
	@LDNS_INCLUDES@

opendnssecdatadir = $(datadir)/opendnssec

if USE_MYSQL
dist_opendnssecdata_DATA = database_create.mysql
else
dist_opendnssecdata_DATA = database_create.sqlite3
endif

bin_PROGRAMS =	ods-ksmutil ods-kaspcheck
man1_MANS =	ods-ksmutil.1 ods-kaspcheck.1

ods_ksmutil_SOURCES = ksmutil.c
ods_ksmutil_LDADD = $(LIBKSM) $(LIBHSM) $(LIBCOMPAT)
ods_ksmutil_LDADD += @XML2_LIBS@ @DB_LIBS@ @LDNS_LIBS@

ods_kaspcheck_SOURCES = kaspcheck.c kaspcheck.h \
						kc_helper.c kc_helper.h

ods_kaspcheck_LDADD = $(LIBHSM) $(LIBCOMPAT)
ods_kaspcheck_LDADD += @XML2_LIBS@

EXTRA_DIST = $(srcdir)/migrate_*.pl
EXTRA_DIST += $(srcdir)/migrate_adapters_1.*
EXTRA_DIST += $(srcdir)/convert_database.pl
EXTRA_DIST += $(srcdir)/migrate_zone_delete.mysql

