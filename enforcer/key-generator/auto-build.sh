#!/bin/sh

aclocal
autoheader
automake --add-missing
autoconf
./configure --prefix=/tmp/jad/opendnssec --with-libksm-include=/tmp/jad/opendnssec/include --with-libksm-lib=/tmp/jad/opendnssec/lib
make clean && make 
