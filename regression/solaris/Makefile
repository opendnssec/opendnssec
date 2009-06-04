# $Id$

TARGETS = softHSM libhsm libksm enforcer signer xml

MAKE_FLAGS = -j 4
TOP = ../../..

CONF_ARG = \
	--prefix=/usr/local \
	--sysconfdir=/etc \
	--localstatedir=/var \
	--with-libksm=/usr/local \
	--with-libhsm=/usr/local \
	--with-sqlite3=/usr/local \
	--with-ldns=/opt/ldns/nossl \
	--with-trang=$(HOME)/bin/trang.jar

all: build

build: $(TARGETS)

install:
	@for t in $(TARGETS); do \
		(cd $$t; make install) \
	done

clean:
	rm -fr $(TARGETS)

$(TARGETS)::
	test -d $@ || mkdir $@
	(cd $@; $(TOP)/$@/configure $(CONF_ARG))
	(cd $@; make $(MAKE_FLAGS))
