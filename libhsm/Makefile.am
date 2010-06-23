# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SUBDIRS = src checks

doxygen:
	INPUT=$(srcdir)/src \
	PROJECT=$(PACKAGE_NAME) \
	VERSION=$(VERSION) \
	doxygen $(srcdir)/libhsm.doxygen
