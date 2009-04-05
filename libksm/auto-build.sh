#!/bin/sh
glibtoolize
aclocal
autoheader
automake --add-missing
autoconf
rm -rf /opt/libksm
./configure --prefix=/opt/libksm --with-mysql=/usr/local/mysql --with-cunit=/usr/local
make clean && make 
