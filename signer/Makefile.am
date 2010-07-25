# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SUBDIRS = src

# TODO: move this to general opendnssec install
install-data-hook:
	$(INSTALL) -d $(DESTDIR)$(localstatedir)
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/tmp
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/signconf
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/unsigned
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/signed
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/run
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/run/opendnssec
