# $Id: Makefile 230 2009-02-27 15:23:09Z rb $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

CLEANFILES = no.token token.db

noinst_PROGRAMS = checks
noinst_DATA = token.db

AM_CFLAGS = -O3 -W -Wall -Werror -g
AM_CPPFLAGS = -I. -I$(srcdir)/../src/lib -I$(srcdir)/../src/lib/cryptoki

EXTRA_DIST =                    *.h

checks_LDADD = ../src/lib/libsofthsm.la


token.db:
	../src/bin/softhsm --init-token $@ --label "A token" --so-pin 12345678 --pin 123456
