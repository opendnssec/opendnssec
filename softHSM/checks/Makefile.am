# $Id: Makefile 230 2009-02-27 15:23:09Z rb $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

noinst_PROGRAMS = checks

AM_CFLAGS = -O3 -W -Wall -Werror -g
AM_CPPFLAGS = -I. -I$(srcdir)/../src/lib -I$(srcdir)/../src/lib/cryptoki

checks_LDADD = ../src/lib/libsofthsm.la
