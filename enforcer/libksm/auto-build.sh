#!/bin/sh
aclocal
OS=`uname -s`
if test $OS = "Darwin"; then
  glibtoolize
else
  libtoolize
fi
autoheader
automake --add-missing
autoconf
rm -rf /opt/libksm
./configure --prefix=/opt/libksm --with-mysql=/usr/local/mysql --with-cunit=/usr/local --with-dbname=test --with-dbhost=test1 --with-dbpass="" --with-dbuser=root
make clean && make 
