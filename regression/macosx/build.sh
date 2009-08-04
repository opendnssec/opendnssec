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
	--with-ldns=/opt/local \
	--with-libxml2=/usr \
	--with-botan=/opt/local \
	--with-pkcs11-softhsm=/usr/local/lib/libsofthsm.dylib \
	--with-pkcs11-etoken=/usr/local/lib/libeTPkcs11.dylib \
	--with-pkcs11-opensc=/Library/OpenSC/lib/pkcs11/opensc-pkcs11.so

make
