# $Id$

ACLOCAL_AMFLAGS = -I m4

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ \
	$(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
	$(srcdir)/config.guess $(srcdir)/config.sub

SUBDIRS = libhsm enforcer conf tools contrib

if ENABLE_SIGNER
SUBDIRS += signer
endif

if ENABLE_AUDITOR
SUBDIRS += auditor
endif

if ENABLE_EPPCLIENT
SUBDIRS += plugins/eppclient
endif

EXTRA_DIST = $(srcdir)/KNOWN_ISSUES
