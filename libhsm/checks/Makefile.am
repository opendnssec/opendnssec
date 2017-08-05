.PHONY: tokens

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
CLEANFILES = token.db othertoken.db

LIBCOMPAT = ${top_builddir}/common/libcompat.a

AM_CPPFLAGS = \
		-I$(top_srcdir)/common \
		-I$(top_builddir)/common \
		-I$(srcdir)/../src/lib \
		@LDNS_INCLUDES@ @XML2_INCLUDES@

AM_CFLAGS =	-std=c99

EXTRA_DIST =	*.xml $(srcdir)/softhsm2.conf

noinst_PROGRAMS = hsmcheck
 
hsmcheck_SOURCES = hsmcheck.c
hsmcheck_LDADD = ../src/lib/libhsm.a $(LIBCOMPAT) @LDNS_LIBS@ @XML2_LIBS@
hsmcheck_LDFLAGS = -no-install

SOFTHSM_ENV = SOFTHSM2_CONF=$(srcdir)/softhsm2.conf


tokens:
	rm -rf tokens
	mkdir tokens
	env $(SOFTHSM_ENV) \
	softhsm2-util --slot 0 --init-token --label softHSM \
		--so-pin 12345678 --pin 123456
	env $(SOFTHSM_ENV) \
	softhsm2-util --slot 1 --init-token --label xyzzy \
		--so-pin 12345678 --pin 123456

check: regress-softhsm

regress:
	@echo use target 'regress-{aepkeyper,sca6000,softhsm,etoken,opensc,ncipher,multi}'

regress-aepkeyper: hsmcheck
	./hsmcheck -c conf-aepkeyper.xml -gsdr

regress-sca6000: hsmcheck
	./hsmcheck -c conf-sca6000.xml -gsdr

regress-softhsm: hsmcheck tokens
	env $(SOFTHSM_ENV) \
	./hsmcheck -c conf-softhsm.xml -gsdr

regress-etoken: hsmcheck
	./hsmcheck -c conf-etoken.xml -gsdr

regress-opensc: hsmcheck
	./hsmcheck -c conf-opensc.xml -gsdr

regress-ncipher: hsmcheck
	./hsmcheck -c conf-ncipher.xml -gsdr

regress-multi: hsmcheck tokens
	env $(SOFTHSM_ENV) \
	./hsmcheck -c conf-multi.xml -gsdr

