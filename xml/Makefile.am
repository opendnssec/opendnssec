# $Id$

ACLOCAL_AMFLAGS = -I m4

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ \
	$(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
	$(srcdir)/config.guess $(srcdir)/config.sub

RNC =	conf.rnc kasp.rnc zonelist.rnc signconf.rnc zonefetch.rnc
RNG =	conf.rng kasp.rng zonelist.rng signconf.rng zonefetch.rng
XML =	conf.xml kasp.xml zonelist.xml signconf.xml zonefetch.xml
XSL=	kasp2html.xsl

TRANG=	$(srcdir)/trang/trang.jar

sysconfdir = @sysconfdir@/opendnssec
datadir = @datadir@/opendnssec

noinst_DATA = ${XML}

dist_data_DATA = ${RNG} ${RNC} ${XSL}

EXTRA_DIST = ${TRANG}

CLEANFILES =	*.rng *.xml

SUFFIXES = .rng .rnc .xml


.rnc.rng:
	@test -x ${JAVA} || \
		(echo "java is required for converting RelaxNG Compact to RelaxNG"; false)
	${JAVA} -jar ${TRANG} $< $@

regress: $(RNG)
	@test -x ${XMLLINT} || \
		(echo "xmllint is required for regression tests"; false)
	@for i in ${XML}; do \
		${XMLLINT} --noout --relaxng \
		 	`basename $$i .xml`.rng \
			$(top_builddir)/$$i; \
	done
	@test -x ${XSLTPROC} || \
		(echo "xsltproc is required for regression tests"; false)
	${XSLTPROC} -o kasp.html kasp2html.xsl kasp.xml
	

install-data-hook:
	test -d ${sysconfdir} || mkdir -p ${DESTDIR}${sysconfdir}
	test -f ${sysconfdir}/conf.xml || \
		${INSTALL_DATA} ${top_builddir}/conf.xml ${DESTDIR}${sysconfdir}
	${INSTALL_DATA} ${top_builddir}/conf.xml ${DESTDIR}${sysconfdir}/conf.xml.sample
	test -f ${sysconfdir}/zonelist.xml || \
		${INSTALL_DATA} ${top_builddir}/zonelist.xml ${DESTDIR}${sysconfdir}
	${INSTALL_DATA} ${top_builddir}/zonelist.xml ${DESTDIR}${sysconfdir}/zonelist.xml.sample
	test -f ${sysconfdir}/zonefetch.xml || \
		${INSTALL_DATA} ${top_builddir}/zonefetch.xml ${DESTDIR}${sysconfdir}
	${INSTALL_DATA} ${top_builddir}/zonefetch.xml ${DESTDIR}${sysconfdir}/zonefetch.xml.sample
	test -f ${sysconfdir}/kasp.xml || \
		${INSTALL_DATA} ${top_builddir}/kasp.xml ${DESTDIR}${sysconfdir}
	${INSTALL_DATA} ${top_builddir}/kasp.xml ${DESTDIR}${sysconfdir}/kasp.xml.sample
