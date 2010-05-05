# $Id: Makefile.am 1104 2009-06-24 07:28:23Z jakob $

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = \
	$(srcdir)/lib/*.rb \
	$(srcdir)/lib/kasp_auditor/*.rb

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
	$(RUBY) -I $(srcdir)/lib $(srcdir)/test_scripts/auditor_test.rb

prepare-test:
	test -d test || (cd $(srcdir); \
	find test -name .svn -prune -o -type f -print |\
	 	cpio -pmdu $(abs_builddir))
