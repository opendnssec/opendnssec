# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS =	-I$(srcdir)/.. \
		-I$(srcdir)/cryptoki
AM_CFLAGS =	-std=c99

lib_LTLIBRARIES = libhsm.la
libhsm_la_SOURCES = libhsm.c
libhsm_la_LDFLAGS = -dl
nobase_include_HEADERS = $(srcdir)/*.h $(srcdir)/cryptoki/*.h
