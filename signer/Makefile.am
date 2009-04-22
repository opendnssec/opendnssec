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
	$(INSTALL) -c -m 664 opendnssec.conf.sample $(DESTDIR)$(sysconfdir)
# and create a var/dnssec dir (where zonelist.xml will go)
	$(INSTALL) -d $(DESTDIR)$(localstatedir)


clean:
	(cd tools; make clean)

realclean:
	(cd tools; make realclean)
	


