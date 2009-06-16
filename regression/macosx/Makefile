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
	--with-sqlite3=/usr \
	--with-ldns=/opt/local \
	--with-libxml2=/usr \
	--with-botan=/opt/local \
	--with-trang=$(HOME)/bin/trang.jar \
	--with-pkcs11-softhsm=/usr/local/lib/libsofthsm.dylib \
	--with-pkcs11-etoken=/usr/local/lib/libeTPkcs11.dylib

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
