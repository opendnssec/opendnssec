#!/bin/sh

aclocal
autoheader
automake --add-missing
autoconf
CFLAGS="-g" ./configure --prefix=/opt/key-gen --with-libksm-include=/home/sion/work/subversion/opendnssec/enforcer/libksm/include --with-libksm-lib=/home/sion/work/subversion/opendnssec/enforcer/libksm/src/.libs
make clean && make 
