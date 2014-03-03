MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

RNC =	addns.rnc conf.rnc kasp.rnc zonelist.rnc signconf.rnc enforcerstate.rnc
RNG =	addns.rng conf.rng kasp.rng zonelist.rng signconf.rng enforcerstate.rng
XML =	addns.xml conf.xml kasp.xml zonelist.xml signconf.xml enforcerstate.xml
XSL=	kasp2html.xsl

TRANG=		$(srcdir)/trang/trang.jar
TRANG_URL	"https://code.google.com/p/jing-trang/"

sysconfdir = @sysconfdir@/opendnssec
datadir = @datadir@/opendnssec

noinst_DATA = ${XML} ${XSL}

dist_data_DATA = ${RNG} ${RNC} ${XSL}

CLEANFILES =+		${XML}
DISTCLEANFILES =+	${RNG}

SUFFIXES = .rng .rnc .xml


$(TRANG):
	@echo You need to manually fetch trang.jar from ${TRANG_URL}
	@echo and copy trang.jar to ${TRANG} before rebuilding
	@echo the RelaxNG schemas.

.rnc.rng:
	@test -x "${JAVA}" || \
		(echo "java is required for converting RelaxNG Compact to RelaxNG"; false)
	${JAVA} -jar ${TRANG} $< $@

regress: $(RNG)
	@test -x "${XMLLINT}" || \
		(echo "xmllint is required for regression tests"; false)
	@for i in ${XML}; do \
		${XMLLINT} --noout --relaxng \
			`basename $$i .xml`.rng $$i || exit 1; \
	done
	@test -x "${XSLTPROC}" || \
		(echo "xsltproc is required for regression tests"; false)
	@${XSLTPROC} -o kasp.html $(srcdir)/kasp2html.xsl kasp.xml && \
		(echo "kasp.xml built")

install-data-hook:
	test -d ${DESTDIR}${sysconfdir} || mkdir -p ${DESTDIR}${sysconfdir}
	test -f ${DESTDIR}${sysconfdir}/conf.xml || \
		${INSTALL_DATA} -m 0640 conf.xml ${DESTDIR}${sysconfdir}
	${INSTALL_DATA} -m 640 conf.xml ${DESTDIR}${sysconfdir}/conf.xml.sample
	test -f ${DESTDIR}${sysconfdir}/addns.xml || \
		${INSTALL_DATA} addns.xml ${DESTDIR}${sysconfdir}
	${INSTALL_DATA} addns.xml ${DESTDIR}${sysconfdir}/addns.xml.sample
	test -f ${DESTDIR}${sysconfdir}/zonelist.xml || \
		${INSTALL_DATA} zonelist.xml ${DESTDIR}${sysconfdir}
	${INSTALL_DATA} zonelist.xml ${DESTDIR}${sysconfdir}/zonelist.xml.sample
	test -f ${DESTDIR}${sysconfdir}/kasp.xml || \
		${INSTALL_DATA} kasp.xml ${DESTDIR}${sysconfdir}
	${INSTALL_DATA} kasp.xml ${DESTDIR}${sysconfdir}/kasp.xml.sample
