# $Id$

nobase_dist_sysconf_DATA = opendnssec/*.xml opendnssec/conf.rng opendnssec/kasp.rng opendnssec/zonelist.rng opendnssec/signconf.rng

opendnssec/%.rng : opendnssec/%.rnc
	@TRANG@ $< $@
	
opendnssec/%.xml : opendnssec/%.rng
	${XMLLINT} --noout --relaxng $< $@
