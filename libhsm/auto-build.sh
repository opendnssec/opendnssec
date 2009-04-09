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
./configure --prefix=/opt/libhsm --with-mysql=/usr/local/mysql --with-cunit=/usr/local --with-dbname=test --with-dbhost=test1 --with-dbpass="" --with-dbuser=root
fi
if [ $OS = "Linux" ]; then
echo "Building for $OS"
./configure --prefix=/opt/libhsm --with-mysql=/usr --with-cunit=/usr/local --with-dbname=test --with-dbhost=test1 --with-dbpass="" --with-dbuser=root
fi
if test $OS = "FreeBSD"; then
echo "Building for $OS"
./configure --prefix=/opt/libhsm --with-mysql=/usr/local --with-cunit=/usr/local --with-dbname=test --with-dbhost=test1 --with-dbpass="" --with-dbuser=root
fi
if test $OS = "SunOS"; then
echo "Building for $OS"
./configure --prefix=/opt/libhsm --with-mysql=/usr/sfw
fi
if test $OS = "SunOS"; then
  gmake clean && gmake
else
  make clean && make && make check
fi
