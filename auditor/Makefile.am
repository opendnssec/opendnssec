# $Id: Makefile.am 1104 2009-06-24 07:28:23Z jakob $

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ \
	$(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
	$(srcdir)/config.guess $(srcdir)/config.sub

install-data-hook:
	${INSTALL} -d 755 $(opendnsseclibdir)
	${INSTALL} -d 755 $(opendnsseclibdir)/kasp_auditor
	${INSTALL_DATA} $(srcdir)/lib/*.rb $(opendnsseclibdir)
	${INSTALL_DATA} $(srcdir)/lib/kasp_auditor/*.rb $(opendnsseclibdir)/kasp_auditor
