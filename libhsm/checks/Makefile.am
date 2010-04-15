# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = token.db othertoken.db

AM_CPPFLAGS = 	-I$(srcdir) \
		-I$(srcdir)/.. \
		-I$(srcdir)/../src \
		@LDNS_INCLUDES@
AM_CFLAGS =	-std=c99

EXTRA_DIST =	*.xml $(srcdir)/softhsm.conf

noinst_PROGRAMS = hsmcheck
 
hsmcheck_LDADD = ../src/libhsm.la @LDNS_LIBS@ @XML2_LIBS@
hsmcheck_LDFLAGS = -no-install

SOFTHSM_ENV = SOFTHSM_CONF=$(srcdir)/softhsm.conf


token.db othertoken.db:
	env $(SOFTHSM_ENV) \
	softhsm --slot 0 --init-token --label softHSM \
		--so-pin 12345678 --pin 123456
	env $(SOFTHSM_ENV) \
	softhsm --slot 1 --init-token --label xyzzy \
		--so-pin 12345678 --pin 123456

check: regress-softhsm

regress:
	@echo use target 'regress-{aepkeyper,sca6000,softhsm,etoken,opensc,ncipher,multi}'

regress-aepkeyper: hsmcheck
	./hsmcheck -f conf-aepkeyper.xml -gsdr

regress-sca6000: hsmcheck
	./hsmcheck -f conf-sca6000.xml -gsdr

regress-softhsm: hsmcheck token.db
	env $(SOFTHSM_ENV) \
	./hsmcheck -f conf-softhsm.xml -gsdr

regress-etoken: hsmcheck
	./hsmcheck -f conf-etoken.xml -gsdr

regress-opensc: hsmcheck
	./hsmcheck -f conf-opensc.xml -gsdr

regress-ncipher: hsmcheck
	./hsmcheck -f conf-ncipher.xml -gsdr

regress-multi: hsmcheck token.db othertoken.db
	env $(SOFTHSM_ENV) \
	./hsmcheck -f conf-multi.xml -gsdr

