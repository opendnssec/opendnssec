# $Id$
#
# Top-level makefile for OpenDNSSEC
#

SUBDIRS = softHSM libhsm libksm enforcer signer auditor xml

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
	--with-libksm=$(PREFIX) \
	--with-libhsm=$(PREFIX) \
	--with-trang=/usr/local/lib/trang.jar

## you may have to add the one or more of the following to CONF_ARG
#
#	--with-sqlite3=/usr/local
#	--with-ldns=/usr/local
#	--with-libxml2=/usr/local
#	--with-botan=/usr/local


all::
	@echo "use 'make autogen build' to build AND install OpenDNSSEC"

autogen::
	@for dir in $(SUBDIRS); do \
		target=`pwd`/$$dir; \
		echo "running autogen.sh in $$target" ;\
		(cd $$target; sh autogen.sh) ;\
		echo "" ;\
	done

build:: $(SUBDIRS)

clean::
	@for dir in $(SUBDIRS); do \
		(cd $(BUILDDIR)/$$dir; $(MAKE) clean );\
	done

$(SUBDIRS)::
	test -d $(BUILDDIR)/$@ || mkdir -p $(BUILDDIR)/$@
	(cd $(BUILDDIR)/$@; $(SRCDIR)/$@/configure $(CONF_ARG))
	$(MAKE) -C $(BUILDDIR)/$@ $(MAKE_FLAGS)
	$(SUDO) $(MAKE) -C $(BUILDDIR)/$@ install

