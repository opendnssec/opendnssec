#!/bin/sh

aclocal
autoheader
automake --add-missing
autoconf
CFLAGS="-g" ./configure  --with-libksm-include=/Users/jad/Desktop/OpenDNSSEC/dnssec/trunk/ksm-enforcer/ksmlib/include --with-libksm-lib=/Users/jad/Desktop/OpenDNSSEC/dnssec/trunk/ksm-enforcer/bin
make clean && make 
