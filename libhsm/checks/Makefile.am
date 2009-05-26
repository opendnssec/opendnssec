# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = token.db

AM_CPPFLAGS = 	-I$(srcdir) \
		-I$(srcdir)/../src
AM_CFLAGS =	-std=c99

EXTRA_DIST =	$(srcdir)/*.xml $(srcdir)/softhsm.conf

noinst_PROGRAMS = hsmtest
noinst_DATA = token.db
 
hsmtest_LDADD = ../src/libhsm.la
hsmtest_LDFLAGS = -no-install


token.db:
	env SOFTHSM_CONF=$(srcdir)/softhsm.conf \
	softhsm --slot 0 --init-token --label softHSM --so-pin 12345678 --pin 123456

regress:
	@echo use target 'regress-sca6000' or 'regress-softhsm'

regress-sca6000:
	env HSMTEST_CONF=conf-sca6000.xml ./hsmtest

regress-softhsm:
	env HSMTEST_CONF=conf-softhsm.xml SOFTHSM_CONF=$(srcdir)/softhsm.conf ./hsmtest
