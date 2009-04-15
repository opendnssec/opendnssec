#!/bin/sh

aclocal
autoheader
automake --add-missing
autoconf
CFLAGS="-g" ./configure --prefix=/opt/key-gen --with-libksm-include=/opt/libksm/include --with-libksm-lib=/opt/libksm/lib
make clean && make 
