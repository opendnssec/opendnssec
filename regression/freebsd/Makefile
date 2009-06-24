# $Id$

TARGETS = softHSM libhsm libksm enforcer signer auditor xml

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
	--with-ldns=/usr/local \
	--with-libxml2=/usr/local \
	--with-botan=/usr/local/botan \
	--without-trang \
	--with-pkcs11-softhsm=/usr/local/lib/libsofthsm.so

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
