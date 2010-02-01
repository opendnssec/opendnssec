# $Id: Makefile.am 2148 2009-10-07 19:56:32Z jakob $

ACLOCAL_AMFLAGS = -I m4

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ \
	$(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
	$(srcdir)/config.guess $(srcdir)/config.sub


SPEC = opendnssec.spec

EXTRA_DIST = $(srcdir)/*.spec.in

dist_data_DATA = ${SPEC}
DISTCLEANFILES =+ ${SPEC}

opendnssec.spec: opendnssec.spec.in
	sed 's/OPENDNSSEC_VERSION/@VERSION@/' < $(srcdir)/opendnssec.spec.in > $@
