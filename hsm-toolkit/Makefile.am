# $Id$

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ \
	$(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
	$(srcdir)/config.guess $(srcdir)/config.sub

AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = -Icryptoki

bin_PROGRAMS = hsm-toolkit

hsm_toolkit_SOURCES =	hsm-toolkit.c pktools.c pktools.h \
			cryptoki/cryptoki.h cryptoki/pkcs11.h \
			cryptoki/pkcs11f.h cryptoki/pkcs11t.h
