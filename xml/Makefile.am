# $Id$

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ \
	$(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
	$(srcdir)/config.guess $(srcdir)/config.sub

AUTOMAKE_OPTIONS = foreign

RNC=    conf.rnc kasp.rnc zonelist.rnc signconf.rnc
RNG=    conf.rng kasp.rng zonelist.rng signconf.rng
XML=    conf.xml kasp.xml zonelist.xml signconf.xml

sysconfdir= @sysconfdir@/opendnssec

dist_sysconf_DATA= ${RNG} ${XML}

CLEANFILES=     *.rng

SUFFIXES= .rng .rnc .xml

.rnc.rng:
	@TRANG@ $< $@

regress:
	for i in ${XML}; do \
		${XMLLINT} --noout --relaxng `basename $$i .xml`.rng $$i; \
	done
