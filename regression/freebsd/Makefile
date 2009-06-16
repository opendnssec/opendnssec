# $Id$

TARGETS = softHSM libhsm libksm enforcer signer xml

SUDO = sudo
MAKE = make
MAKE_FLAGS =

TOP = ../../..

CONF_ARG = \
	--prefix=/usr/local \
	--sysconfdir=/etc \
	--localstatedir=/var \
	--with-libksm=/usr/local \
	--with-libhsm=/usr/local \
	--with-sqlite3=/usr/local \
	--with-ldns=/opt/local \
	--with-libxml2=/usr/local \
	--with-botan=/usr/local/botan \
	--without-trang \
	--with-softhsm=/usr/local/lib/libsofthsm.dylib

all: build

build: $(TARGETS)

install:
	@for t in $(TARGETS); do \
		$(MAKE) $$t ;\
		(cd $$t; $(SUDO) $(MAKE) install) \
	done

clean:
	rm -fr $(TARGETS)

$(TARGETS)::
	test -d $@ || mkdir $@
	(cd $@; $(TOP)/$@/configure $(CONF_ARG))
	(cd $@; $(MAKE) $(MAKE_FLAGS))
