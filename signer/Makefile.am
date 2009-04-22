srcdir=@srcdir@
libdir=@libdir@
sysconfdir=@sysconfdir@
localstatedir=@localstatedir@
INSTALL = $(srcdir)/install-sh 

all:
	(cd tools; make all)

install:
	(cd tools; make install)
# install the engine
	$(INSTALL) -d $(DESTDIR)$(libdir)python/signer_engine/
	for i in signer_engine/*.py; do \
		$(INSTALL) -c -m 664 $$i $(DESTDIR)$(libdir)/python/$$i ; \
	done
# start script and command line interface
	$(INSTALL) -c -m 755 signer_engine/signer_engine $(DESTDIR)$(bindir)
	$(INSTALL) -c -m 755 signer_engine/signer_engine_cli $(DESTDIR)$(bindir)
# and the configuration (TODO: move this to general opendnssec install!)
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)/opendnssec
	$(INSTALL) -c -m 664 conf.xml.sample $(DESTDIR)$(sysconfdir)/opendnssec
# and create a var/opendnssec dir (where zonelist.xml will go)
	$(INSTALL) -d $(DESTDIR)$(localstatedir)
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/tmp
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/signconf
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/unsigned
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/signed


clean:
	(cd tools; make clean)

realclean:
	(cd tools; make realclean)
	


