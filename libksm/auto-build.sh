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
echo "Building for $OS"
if test $OS = "Darwin"; then
echo "Building for $OS"
./configure --prefix=/opt/libksm --with-mysql=/usr/local/mysql --with-cunit=/usr/local --with-dbname=test --with-dbhost=test1 --with-dbpass="" --with-dbuser=root
fi
if [ $OS = "Linux" ]; then
echo "Building for $OS"
CFLAGS="-g" ./configure --prefix=/opt/libksm --with-sqlite3=/usr --with-cunit=/usr --with-dbname=ksm --with-dbhost=localhost --with-dbpass=ksm_test --with-dbuser=ksm_test
#CFLAGS="-g" ./configure --prefix=/opt/libksm --with-mysql=/usr --with-cunit=/usr --with-dbname=ksm --with-dbhost=localhost --with-dbpass=ksm_test --with-dbuser=ksm_test
fi
if test $OS = "FreeBSD"; then
echo "Building for $OS"
./configure --prefix=/opt/libksm --with-mysql=/usr/local --with-cunit=/usr/local --with-dbname=test --with-dbhost=test1 --with-dbpass="" --with-dbuser=root
fi
if test $OS = "SunOS"; then
echo "Building for $OS"
./configure --prefix=/opt/libksm --with-mysql=/usr/sfw
fi
if test $OS = "SunOS"; then
  gmake clean && gmake
else
  make clean && make && make check
fi
