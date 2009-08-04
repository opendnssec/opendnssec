#!/bin/sh
#
# $Id$

../../configure \
	--prefix=/usr/local \
	--sysconfdir=/etc \
	--localstatedir=/var \
	--with-libksm=/usr/local \
	--with-libhsm=/usr/local \
	--with-sqlite3=/usr/local \
	--with-ldns=/usr/local \
	--with-libxml2=/usr/local \
	--with-botan=/usr/local/botan \
	--without-trang \
	--with-pkcs11-softhsm=/usr/local/lib/libsofthsm.so

make
