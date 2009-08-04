# $Id$

PREFIX = /usr/local

CONFIGURE_ARGS = \
	--prefix=$(PREFIX) \
	--sysconfdir=/etc \
	--localstatedir=/var \
	--with-sqlite3=/usr \
	--with-ldns=/opt/local \
	--with-libxml2=/usr \
	--with-botan=/opt/local \
	--with-pkcs11-softhsm=$(PREFIX)/libsofthsm.dylib \
	--with-pkcs11-etoken=/usr/local/lib/libeTPkcs11.dylib \
	--with-pkcs11-opensc=/Library/OpenSC/lib/pkcs11/opensc-pkcs11.so

SUDO = sudo
MAKE = make

include ../Makefile.inc
