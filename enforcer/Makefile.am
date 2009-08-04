# $Id: Makefile.am 615 2009-05-06 08:52:03Z jakob $

ACLOCAL_AMFLAGS = -I m4

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ \
	$(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
	$(srcdir)/config.guess $(srcdir)/config.sub

SUBDIRS = ksm common communicated keygend utils

install-data-hook:
	mkdir -p ${DESTDIR}$(localstatedir)/run/opendnssec
	mkdir -p ${DESTDIR}$(localstatedir)/opendnssec
