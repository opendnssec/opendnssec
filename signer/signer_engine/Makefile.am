# $Id$

install:
	$(INSTALL) -d $(DESTDIR)$(libdir)/opendnssec/signer/
	for i in *.py; do \
		$(INSTALL) -c -m 664 $$i $(DESTDIR)$(libdir)/opendnssec/signer/$$i ; \
	done
	$(INSTALL) -c -m 755 signer_engine $(DESTDIR)$(bindir)
	$(INSTALL) -c -m 755 signer_engine_cli $(DESTDIR)$(bindir)
