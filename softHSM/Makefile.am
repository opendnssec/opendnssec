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

SUBDIRS = src checks


install-data-hook:
	test -f ${sysconfdir}/softhsm.conf || \
		${INSTALL_DATA} ${srcdir}/softhsm.conf ${sysconfdir}
	${INSTALL} -d -m 700 ${softhsmdbdir}
