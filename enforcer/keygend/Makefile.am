# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = -pedantic -Wall -I@KSM_INCLUDES@ @XML_INCLUDES@

bin_PROGRAMS = keygend
keygend_SOURCES = daemon.c daemon_util.c keygend.c keygend_util.c kaspaccess.c

keygend_LDFLAGS = -L@KSM_LIBS@ -lksm @XML_LIBS@

EXTRA_DIST = *.h
