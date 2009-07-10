# $Id$

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ \
	$(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
	$(srcdir)/config.guess $(srcdir)/config.sub

RNC =	conf.rnc kasp.rnc zonelist.rnc signconf.rnc
RNG =	conf.rng kasp.rng zonelist.rng signconf.rng
XML =	conf.xml kasp.xml zonelist.xml signconf.xml

sysconfdir = @sysconfdir@/opendnssec

dist_sysconf_DATA = ${RNG} ${RNC}

CLEANFILES =	*.rng

SUFFIXES = .rng .rnc .xml

.rnc.rng:
	@test "x@TRANG@" != "x" || \
		(echo "trang is required to (re)build XML schemas"; false)
	@TRANG@ $< $@

regress: $(RNG)
	@test -x ${XMLLINT} || \
		(echo "xmllint is required for regression tests"; false)
	@for i in ${XML}; do \
		${XMLLINT} --noout --relaxng \
		 	`basename $$i .xml`.rng \
			$(top_builddir)/$$i; \
	done

install-data-hook:
	test -f ${sysconfdir}/conf.xml || \
		${INSTALL_DATA} ${top_builddir}/conf.xml ${sysconfdir}
	${INSTALL_DATA} ${top_builddir}/conf.xml ${sysconfdir}/conf.xml.sample
	test -f ${sysconfdir}/zonelist.xml || \
		${INSTALL_DATA} ${top_builddir}/zonelist.xml ${sysconfdir}
	${INSTALL_DATA} ${top_builddir}/zonelist.xml ${sysconfdir}/zonelist.xml.sample
	test -f ${sysconfdir}/kasp.xml || \
		${INSTALL_DATA} ${top_builddir}/kasp.xml ${sysconfdir}
	${INSTALL_DATA} ${top_builddir}/kasp.xml ${sysconfdir}/kasp.xml.sample
