# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = -I$(srcdir)/../common

bin_PROGRAMS = keygend

keygend_SOURCES = keygend.c keygend_util.c
keygend_LDADD = ../common/libenforcer.a
keygend_LDFLAGS = -L@KSM_LIBS@ -lksm @XML_LIBS@

EXTRA_DIST = *.h
