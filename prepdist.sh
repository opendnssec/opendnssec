#!/bin/sh
#
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
	--with-pkcs11-softhsm=/usr/local/lib/softhsm/libsofthsm2.so \
	$@
