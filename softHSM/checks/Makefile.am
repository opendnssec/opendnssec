# $Id: Makefile 230 2009-02-27 15:23:09Z rb $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

CLEANFILES = no.token token.db

noinst_PROGRAMS = checks
noinst_DATA = token.db

AM_CPPFLAGS = 	-I$(srcdir) -I$(srcdir)/../src/lib -I$(srcdir)/../src/lib/cryptoki \
		-DCHECKS_SOFTHSM_CONF='"$(srcdir)/softhsm.conf"'

EXTRA_DIST =	$(srcdir)/*.h \
		$(srcdir)/softhsm.conf

checks_LDADD = ../src/lib/libsofthsm.la -lstdc++
checks_LDFLAGS = -no-install

token.db:
	../src/bin/softhsm --init-token $@ --label "A token" --so-pin 12345678 --pin 123456
