# $Id$

PREFIX = /usr/local

CONFIGURE_ARGS = \
	--prefix=$(PREFIX) \
	--sysconfdir=/etc \
	--localstatedir=/var \
	--with-sqlite3=/usr/local \
	--with-ldns=/usr/local \
	--with-libxml2=/usr/local \
	--with-botan=/usr/local/botan \
	--with-pkcs11-softhsm=$(PREFIX)/lib/libsofthsm.so

MAKE = make
SUDO = sudo

include ../Makefile.inc
