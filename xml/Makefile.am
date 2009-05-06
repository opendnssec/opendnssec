# $Id$

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