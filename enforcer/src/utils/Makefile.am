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
	@LDNS_INCLUDES@

opendnssecdatadir = $(datadir)/opendnssec

bin_PROGRAMS = ods-kaspcheck
dist_man1_MANS = ods-kaspcheck.1

ods_kaspcheck_SOURCES = kaspcheck.c kaspcheck.h \
						kc_helper.c kc_helper.h

ods_kaspcheck_LDADD = $(LIBHSM) $(LIBCOMPAT)
ods_kaspcheck_LDADD += @XML2_LIBS@
