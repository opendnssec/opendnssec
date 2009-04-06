#!/bin/sh

aclocal
autoheader
automake --add-missing
autoconf
CFLAGS="-g" ./configure --prefix=/opt/key-gen --with-libksm-include=/Users/jad/Desktop/OpenDNSSEC/dnssec/trunk/libksm/include --with-libksm-lib=/opt/libksm/lib
make clean && make 
