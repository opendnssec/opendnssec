#!/bin/sh
#
# $Id: prepdist.sh 5999 2012-01-04 14:45:36Z jakob $

PREFIX=/tmp/opendnssec-release

if [ ! -f autogen.sh -a ! -f configure ]; then
        echo "Unable to continue, no autogen.sh or configure"
        exit 1
fi

if [ -f autogen.sh ]; then 
        sh autogen.sh 
fi &&
mkdir -p build &&
cd build &&
../configure --prefix=${PREFIX} \
	--with-database-backend=sqlite3 \
	--with-dbname=opendnssec-release-test \
	--with-pkcs11-softhsm=/usr/local/lib/softhsm/libsofthsm.so \
	$@
