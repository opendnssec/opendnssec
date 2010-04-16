# $Id: Makefile.am 2766 2010-02-01 16:19:49Z rb $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS =	-I$(srcdir)/.. \
		@LDNS_INCLUDES@ @XML2_INCLUDES@ \
		@LIBCURL_CPPFLAGS@ @SQLITE3_INCLUDES@
AM_CFLAGS =	-std=c99 -D_XOPEN_SOURCE=600

COMPAT =	compat/strlcpy.c

sysconfdir =	@sysconfdir@/opendnssec

man5_MANS = eppclientd.conf.5
man8_MANS = eppclient.8 eppclientd.8

sbin_PROGRAMS = eppclient eppclientd

eppclient_SOURCES = eppclient.c eppconfig.c $(COMPAT)
eppclient_LDADD = @LDNS_LIBS@ @XML2_LIBS@ @SQLITE3_LIBS@

eppclientd_SOURCES = eppclientd.c eppconfig.c epp.c $(COMPAT)
eppclientd_LDADD = @LDNS_LIBS@ @XML2_LIBS@ @LIBCURL@ @SQLITE3_LIBS@

EXTRA_DIST = $(srcdir)/eppclientd.conf.in $(srcdir)/*.h
EXTRA_DIST += $(srcdir)/compat/*.c $(srcdir)/compat/*.h


install-data-hook:
	test -d ${DESTDIR}${sysconfdir} || mkdir -p ${DESTDIR}${sysconfdir}
	test -f ${DESTDIR}${sysconfdir}/eppclientd.conf || \
		${INSTALL_DATA} eppclientd.conf ${DESTDIR}${sysconfdir}
