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
	--with-cunit=/usr/local \
	--with-ldns=/opt/ldns/nossl \
	--with-libxml2=/usr \
	--with-botan=/usr/local

make
