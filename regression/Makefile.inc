# $Id$

BUILDDIR = obj


all: build

configure: $(BUILDDIR)/Makefile

$(BUILDDIR)/Makefile: $(BUILDDIR)
	cd $(BUILDDIR); ../../../configure $(CONFIGURE_ARGS)

build: configure
	cd $(BUILDDIR); $(MAKE)
    
install:
	cd $(BUILDDIR); $(SUDO) $(MAKE) install

$(BUILDDIR):
	-mkdir $(BUILDDIR)

clean:
	rm -fr $(BUILDDIR)
