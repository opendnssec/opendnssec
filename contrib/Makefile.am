# $Id: Makefile.am 2148 2009-10-07 19:56:32Z jakob $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SPEC = opendnssec.spec

EXTRA_DIST = $(srcdir)/*.spec.in

dist_data_DATA = ${SPEC}
DISTCLEANFILES =+ ${SPEC}

opendnssec.spec: opendnssec.spec.in
	sed 's/OPENDNSSEC_VERSION/@VERSION@/' < $(srcdir)/opendnssec.spec.in > $@
