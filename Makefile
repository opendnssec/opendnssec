# $Id$

SUBDIRS = softHSM libhsm libksm enforcer signer xml

PREFIX = /usr/local
BUILDDIR = build

SUDO =
MAKE = make
MAKE_FLAGS =

CONF_ARG = \
	--prefix=$(PREFIX) \
	--sysconfdir=/etc \
	--localstatedir=/var \
	--with-libksm=$(PREFIX) \
	--with-libhsm=$(PREFIX)

#	--with-sqlite3=/usr
#	--with-ldns=/usr
#	--with-libxml2=/usr
#	--with-botan=/usr


all:
	@echo "use 'make configure build' to build AND install OpenDNSSEC"

configure: autogen

autogen:
	@for dir in $(SUBDIRS); do \
		target=`pwd`/$$dir; \
		echo "running autogen.sh in $$target" ;\
		(cd $$target; sh autogen.sh) ;\
		echo "" ;\
	done

build:
	@for dir in $(SUBDIRS); do \
		source=`pwd`/$$dir; \
		target=$(BUILDDIR)/$$dir ;\
		echo "building in $$target" ;\
		test -d $$target || mkdir -p $$target ;\
		(cd $$target; $$source/configure $(CONF_ARG)) ;\
		(cd $$target; $(MAKE) $(MAKE_FLAGS)) ;\
		(cd $$target; $(SUDO) $(MAKE) install) ;\
		echo "" ;\
	done
