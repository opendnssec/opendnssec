# $Id$
#
# Top-level makefile for OpenDNSSEC
#

SUBDIRS = softHSM libhsm libksm enforcer signer xml

PREFIX = /usr/local
SRCDIR != pwd
SRCDIR ?= $(shell pwd)
BUILDDIR = build

SUDO = sudo
MAKE = make
MAKE_FLAGS =

CONF_ARG = \
	--prefix=$(PREFIX) \
	--sysconfdir=/etc \
	--localstatedir=/var \
	--with-trang=/usr/local/lib/trang.jar

## you may have to add the one or more of the following to CONF_ARG
#
#	--with-sqlite3=/usr/local
#	--with-ldns=/usr/local
#	--with-libxml2=/usr/local
#	--with-botan=/usr/local


all:
	@echo "use 'make autogen configure build install' to build and install OpenDNSSEC"

autogen:
	@for dir in $(SUBDIRS); do \
		target=`pwd`/$$dir; \
		echo "running autogen.sh in $$target" ;\
		(cd $$target; sh autogen.sh) ;\
		echo "" ;\
	done

configure:
	@for dir in $(SUBDIRS); do \
		test -d $(BUILDDIR)/$$dir || mkdir -p $(BUILDDIR)/$$dir ;\
		echo "running configure in $(BUILDDIR)/$$dir" ;\
		(cd $(BUILDDIR)/$$dir; $(SRCDIR)/$$dir/configure $(CONF_ARG)) ||\
		exit ;\
	done

build:: $(SUBDIRS)

clean:
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $(BUILDDIR)/$$dir clean ;\
	done

$(SUBDIRS)::
	$(MAKE) -C $(BUILDDIR)/$@ $(MAKE_FLAGS)

install:
	@for dir in $(SUBDIRS); do \
		echo "running install in $(BUILDDIR)/$$dir" ;\
		$(SUDO) $(MAKE) -C $(BUILDDIR)/$$dir install ;\
		echo "" ;\
	done
