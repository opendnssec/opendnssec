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
	$(INSTALL) -c -m 664 engine/*.py $(DESTDIR)$(libdir)python/signer_engine/
# and the start script
	$(INSTALL) -c -m 755 engine/signer_engine $(DESTDIR)$(bindir)
# and the configuration (TODO: move this to general opendnssec install!)
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)
	$(INSTALL) -c -m 664 opendnssec.conf $(DESTDIR)$(sysconfdir)
# and create a var/dnssec dir (where zonelist.xml will go)
	$(INSTALL) -d $(DESTDIR)$(localstatedir)


clean:
	(cd tools; make clean)

realclean:
	(cd tools; make realclean)
	


