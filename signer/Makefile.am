srcdir=@srcdir@
libdir=@libdir@
INSTALL = $(srcdir)/install-sh 

all:
	(cd tools; make all)

install:
	(cd tools; make install)
# install the engine
	$(INSTALL) -d $(DESTDIR)$(libdir)/python/signer_engine/
	$(INSTALL) -c -m 664 engine/*.py $(DESTDIR)$(libdir)/python/signer_engine/
# and the start script
	$(INSTALL) -c -m 755 engine/signer_engine $(DESTDIR)$(bindir)

clean:
	(cd tools; make clean)

realclean:
	(cd tools; make realclean)
	


