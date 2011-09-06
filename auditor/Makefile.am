# $Id: Makefile.am 1104 2009-06-24 07:28:23Z jakob $

ACLOCAL_AMFLAGS = -I m4
RDOC = rdoc

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ \
	$(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
	$(srcdir)/config.guess $(srcdir)/config.sub

opendnsseclibdir = $(libdir)/opendnssec

bin_SCRIPTS =	ods-auditor ods-kaspcheck

man1_MANS =	ods-auditor.1 ods-kaspcheck.1

install-data-hook:
	${INSTALL} -d -m 755 ${DESTDIR}$(opendnsseclibdir)
	${INSTALL} -d -m 755 ${DESTDIR}$(opendnsseclibdir)/kasp_auditor
	${INSTALL_DATA} $(srcdir)/lib/*.rb ${DESTDIR}$(opendnsseclibdir)
	${INSTALL_DATA} $(srcdir)/lib/kasp_auditor/*.rb ${DESTDIR}$(opendnsseclibdir)/kasp_auditor
	${INSTALL_DATA} $(builddir)/lib/kasp_auditor/*.rb ${DESTDIR}$(opendnsseclibdir)/kasp_auditor


check: prepare-test
	$(RUBY) -I $(srcdir)/lib -I $(builddir)/lib $(srcdir)/test_scripts/auditor_test.rb

prepare-test:
	test -d test || (cd $(srcdir); \
	find test -name .svn -prune -o -type f -print |\
	 	cpio -pmdu $(abs_builddir))

rdoc:
	rm -fr $(builddir)/doc
	$(RDOC) \
		--exclude ${srcdir}/test \
		--exclude ${builddir}/test \
		${srcdir} ${builddir}

EXTRA_DIST =	$(srcdir)/lib/*.rb \
		$(srcdir)/lib/kasp_auditor/*.rb \
		$(srcdir)/sorttest.txt \
		$(srcdir)/test_scripts/*.rb \
		$(srcdir)/test/kaspcheck_bad/*.xml \
		$(srcdir)/test/kaspcheck_good/*.xml \
		$(srcdir)/test/signer_test_bad/*.xml \
		$(srcdir)/test/signer_test_bad/*.partial \
		$(srcdir)/test/signer_test_bad/signed_zones/*.nsec \
		$(srcdir)/test/signer_test_bad/signed_zones/*.nsec3 \
		$(srcdir)/test/signer_test_bad/zone_config/*.nsec \
		$(srcdir)/test/signer_test_bad/zone_config/*.nsec3 \
		$(srcdir)/test/signer_test_bad/zone_config/*.partial \
		$(srcdir)/test/signer_test_good/*.xml \
		$(srcdir)/test/signer_test_good/signed_zones/*.nsec \
		$(srcdir)/test/signer_test_good/signed_zones/*.nsec3 \
		$(srcdir)/test/signer_test_good/zone_config/*.nsec \
		$(srcdir)/test/signer_test_good/zone_config/*nsec3 \
		$(srcdir)/test/tmp/*.inbound \
		$(srcdir)/test/tmp1/*.inbound \
		$(srcdir)/test/tmp2/*.inbound \
		$(srcdir)/test/tmp3/*.inbound \
		$(srcdir)/test/tmp3/tracker/*.nl \
		$(srcdir)/test/tmp3/tracker/*.config
