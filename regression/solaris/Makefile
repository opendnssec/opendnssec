# $Id$

TARGETS = softHSM libhsm libksm enforcer signer xml

TOP = ../../..

CONF_ARG = \
	--prefix=/usr/local \
	--sysconfdir=/etc \
	--localstatedir=/var \
	--with-libksm=/usr/local \
	--with-libhsm=/usr/local \
	--with-ldns=/opt/ldns/nossl \
	--with-trang=$(HOME)/bin/trang.jar

all: build

build: $(TARGETS)

clean:
	rm -fr $(TARGETS)

$(TARGETS)::
	test -d $@ || mkdir $@
	(cd $@; $(TOP)/$@/configure $(CONF_ARG))
	(cd $@; make)
