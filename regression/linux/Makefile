# $Id$

TARGETS = softHSM libhsm libksm enforcer signer xml

TOP = ../../..

CONF_ARG = \
	--prefix=/usr/local \
	--sysconfdir=/etc \
	--localstatedir=/var \
	--with-libksm=/usr/local \
	--with-libhsm=/usr/local \
	--with-sqlite3=/usr \
	--with-ldns=/usr \
	--with-trang=$(HOME)/bin/trang.jar

all: build

build: $(TARGETS)

install:
	@for TARGET in $(TARGETS); do \
		(cd $$TARGET; make install) \
	done

clean:
	rm -fr $(TARGETS)

$(TARGETS)::
	test -d $@ || mkdir $@
	(cd $@; $(TOP)/$@/configure $(CONF_ARG))
	(cd $@; make)
