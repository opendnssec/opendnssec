#!/bin/sh

aclocal
autoheader
automake --add-missing
autoconf
CFLAGS="-g" ./configure --prefix=/opt/communicator --with-libksm-include=../../libksm/include --with-libksm-lib=../../libksm/src/.libs
make clean && make 
