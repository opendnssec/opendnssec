# $Id: Makefile.am 2766 2010-02-01 16:19:49Z rb $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS =	-I$(srcdir)/.. \
		@LDNS_INCLUDES@ @XML2_INCLUDES@ \
		@CURL_INCLUDES@ @SQLITE3_INCLUDES@
AM_CFLAGS =	-std=c99

COMPAT =	compat/strlcpy.c compat/strlcat.c

sbin_PROGRAMS = eppclient eppclientd

eppclient_SOURCES = eppclient.c eppconfig.c $(COMPAT)
eppclient_LDADD = @XML2_LIBS@ @SQLITE3_LIBS@

eppclientd_SOURCES = eppclientd.c eppconfig.c epp.c $(COMPAT)
eppclientd_LDADD = @LDNS_LIBS@ @XML2_LIBS@ @CURL_LIBS@ @SQLITE3_LIBS@

EXTRA_DIST = $(srcdir)/eppclientd.conf
EXTRA_DIST += $(srcdir)/compat/*.c $(srcdir)/compat/*.h
