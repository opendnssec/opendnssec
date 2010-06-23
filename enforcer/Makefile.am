# $Id: Makefile.am 615 2009-05-06 08:52:03Z jakob $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SUBDIRS = ksm common enforcerd utils test

install-data-hook:
	mkdir -p ${DESTDIR}$(localstatedir)/run/opendnssec
	mkdir -p ${DESTDIR}$(localstatedir)/opendnssec
