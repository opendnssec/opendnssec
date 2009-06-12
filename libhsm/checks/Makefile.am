# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = token.db

AM_CPPFLAGS = 	-I$(srcdir) \
		-I$(srcdir)/.. \
		-I$(srcdir)/../src
AM_CFLAGS =	-std=c99

EXTRA_DIST =	$(srcdir)/*.xml $(srcdir)/softhsm.conf

noinst_PROGRAMS = hsmtest hsmspeed
 
hsmtest_LDADD = ../src/libhsm.la
hsmtest_LDFLAGS = -no-install

hsmspeed_LDADD = ../src/libhsm.la
hsmspeed_LDFLAGS = -no-install -lpthread

SOFTHSM_ENV = SOFTHSM_CONF=$(srcdir)/softhsm.conf


token.db:
	env $(SOFTHSM_ENV) \
	softhsm --slot 0 --init-token --label softHSM \
		--so-pin 12345678 --pin 123456

regress:
	@echo use target 'regress-sca6000' or 'regress-softhsm'

regress-sca6000:
	./hsmtest -f conf-sca6000.xml -gsdr

regress-softhsm: token.db
	env $(SOFTHSM_ENV) \
	./hsmtest -f conf-softhsm.xml -gsdr
