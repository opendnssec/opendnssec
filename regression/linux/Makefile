# $Id$

PREFIX = /usr/local

CONFIGURE_ARGS = \
	--prefix=$(PREFIX) \
	--sysconfdir=/etc \
	--localstatedir=/var \
	--with-sqlite3=/usr \
	--with-ldns=/usr \
	--with-libxml2=/usr \
	--with-botan=/usr \
	--with-pkcs11-softhsm=$(PREFIX)/lib/libsofthsm.so

SUDO = sudo
MAKE = make

include ../Makefile.inc
