#!/bin/sh
#
# $Id$

../../configure \
	--prefix=/usr/local \
	--sysconfdir=/etc \
	--localstatedir=/var \
	--with-libksm=/usr/local \
	--with-libhsm=/usr/local \
	--with-sqlite3=/usr \
	--with-ldns=/usr \
	--with-libxml2=/usr \
	--with-botan=/usr \
	--with-pkcs11-softhsm=/usr/local/lib/libsofthsm.so

make
