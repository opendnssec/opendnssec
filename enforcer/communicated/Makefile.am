# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = -I$(srcdir)/../common

sbin_PROGRAMS = communicated

communicated_SOURCES = communicator.c
communicated_LDADD = ../common/libenforcer.a
communicated_LDFLAGS = @RUNTIME_PATH@ -L@KSM_LIBS@ -lksm @XML_LIBS@

EXTRA_DIST = $(srcdir)/*.h
