# $Id$

SUBDIRS = softHSM libhsm libksm enforcer signer xml

PREFIX = /usr/local
BUILDDIR = build

SUDO = sudo
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
#	--with-trang=/usr/local/lib/trang.jar


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

$(SUBDIRS)::
	test -d $(BUILDDIR)/$@ || mkdir -p $(BUILDDIR)/$@
	(cd $(BUILDDIR)/$@; ../../$@/configure $(CONF_ARG))
	$(MAKE) -C $(BUILDDIR)/$@ $(MAKE_FLAGS)
	$(SUDO) $(MAKE) -C $(BUILDDIR)/$@ install
