# $Id$

PREFIX = /usr/local

CONFIGURE_ARGS = \
	--prefix=$(PREFIX) \
	--sysconfdir=/etc \
	--localstatedir=/var \
	--with-sqlite3=/usr/local \
	--with-cunit=/usr/local \
	--with-ldns=/opt/ldns/nossl \
	--with-libxml2=/usr \
	--with-botan=/usr/local

SUDO = sudo
MAKE = make -j 4

include ../Makefile.inc
