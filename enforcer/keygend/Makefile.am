# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = -I$(srcdir)/../common

sbin_PROGRAMS = keygend

keygend_SOURCES = keygend.c
keygend_LDADD = ../common/libenforcer.a

EXTRA_DIST = $(srcdir)/*.h
