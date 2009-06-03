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


AUTOMAKE_OPTIONS = foreign

SUBDIRS = src checks

doxygen:
	INPUT=$(srcdir)/src \
	PROJECT=$(PACKAGE_NAME) \
	VERSION=$(VERSION) \
	doxygen $(srcdir)/libhsm.doxygen
