# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = token.db othertoken.db

AM_CPPFLAGS = 	-I$(srcdir) \
		-I$(srcdir)/.. \
		-I$(srcdir)/../src \
		@LDNS_INCLUDES@
AM_CFLAGS =	-std=c99

EXTRA_DIST =	$(srcdir)/*.xml $(srcdir)/softhsm.conf

noinst_PROGRAMS = hsmtest hsmspeed
 
hsmtest_LDADD = ../src/libhsm.la @LDNS_LIBS@ @XML2_LIBS@
hsmtest_LDFLAGS = -no-install

hsmspeed_LDADD = ../src/libhsm.la -lpthread @LDNS_LIBS@ @XML2_LIBS@
hsmspeed_LDFLAGS = -no-install

SOFTHSM_ENV = SOFTHSM_CONF=$(srcdir)/softhsm.conf


token.db othertoken.db:
	env $(SOFTHSM_ENV) \
	softhsm --slot 0 --init-token --label softHSM \
		--so-pin 12345678 --pin 123456
	env $(SOFTHSM_ENV) \
	softhsm --slot 1 --init-token --label xyzzy \
		--so-pin 12345678 --pin 123456

regress:
	@echo use target 'regress-{sca6000,softhsm,etoken,opensc,multi}'

regress-sca6000: hsmtest
	./hsmtest -f conf-sca6000.xml -gsdr

regress-softhsm: hsmtest token.db
	env $(SOFTHSM_ENV) \
	./hsmtest -f conf-softhsm.xml -gsdr

regress-etoken: hsmtest
	./hsmtest -f conf-etoken.xml -gsdr

regress-opensc: hsmtest
	./hsmtest -f conf-opensc.xml -gsdr

regress-multi: hsmtest token.db othertoken.db
	env $(SOFTHSM_ENV) \
	./hsmtest -f conf-multi.xml -gsdr

