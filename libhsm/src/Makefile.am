# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = -I$(srcdir)/cryptoki -D__EXTENSIONS__
AM_CFLAGS = -std=c99

lib_LTLIBRARIES = libhsm.la
libhsm_la_SOURCES = libhsm.c
libhsm_la_LDFLAGS = -dl
nobase_include_HEADERS = *.h cryptoki/*.h

noinst_PROGRAMS = hsmtest
hsmtest_LDADD = libhsm.la
