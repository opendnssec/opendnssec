# $Id$

SUBDIRS = tools signer_engine


# TODO: move this to general opendnssec install
install-data-hook:
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)/opendnssec
	$(INSTALL) -c -m 664 conf.xml.sample $(DESTDIR)$(sysconfdir)/opendnssec
	$(INSTALL) -d $(DESTDIR)$(localstatedir)
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/tmp
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/signconf
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/unsigned
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/signed
