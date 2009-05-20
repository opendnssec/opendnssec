# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = token.db

AM_CPPFLAGS = 	-I$(srcdir) \
		-I$(srcdir)/../src \
		-I$(srcdir)/../src/cryptoki
AM_CFLAGS =	-std=c99

EXTRA_DIST =	$(srcdir)/*.xml

noinst_PROGRAMS = hsmtest
noinst_DATA = token.db
 
#hsmtest_LDADD = ../src/libhsm.la
hsmtest_LDADD = ../src/.libs/libhsm.a
hsmtest_LDFLAGS = -no-install


token.db:
	softhsm --init-token $@ --label "theToken" --so-pin 12345678 --pin 123456

regress:
	@echo use target 'regress-sca6000' or 'regress-softhsm'

regress-sca6000:
	env HSMTEST_CONF=conf-sca6000.xml ./hsmtest

regress-softhsm:
	env HSMTEST_CONF=conf-softhsm.xml SOFTHSM_CONF=$(srcdir)/softhsm.conf ./hsmtest
