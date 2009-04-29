#!/bin/sh

cd /
rm -rf /tmp/jad
cd /tmp
mkdir jad
cd jad
mkdir opendnssec
cd opendnssec
mkdir build
cd build
svn co svn+ssh://keihatsu.kirei.se/svn/dnssec/trunk
#tar -xzf /tmp/enforcer.tgz
cd trunk/enforcer

cd libksm
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
./configure --prefix=/tmp/jad/opendnssec --with-mysql=/usr/local/mysql --with-cunit=/usr/local --with-dbname=test --with-dbhost=test1 --with-dbpass="" --with-dbuser=root
fi
if [ $OS = "Linux" ]; then
echo "Building for $OS"
./configure --prefix=/tmp/jad/opendnssec --with-mysql=/usr --with-cunit=/usr --with-dbname=ksm --with-dbhost=localhost --with-dbpass=ksm_test --with-dbuser=ksm_test
fi
if test $OS = "FreeBSD"; then
echo "Building for $OS"
./configure --prefix=/tmp/jad/opendnssec --with-mysql=/usr/local --with-cunit=/usr/local --with-dbname=test --with-dbhost=test1 --with-dbpass="" --with-dbuser=root
fi
if test $OS = "SunOS"; then
echo "Building for $OS"
./configure --prefix=/tmp/jad/opendnssec --with-mysql=/usr/sfw
fi
if test $OS = "SunOS"; then
  gmake clean && gmake & gmake install
else
  make clean && make && make install
fi

cd ../key-generator
aclocal
autoheader
automake --add-missing
autoconf
./configure --prefix=/tmp/jad/opendnssec --with-libksm-include=/tmp/jad/opendnssec/include --with-libksm-lib=/tmp/jad/opendnssec/lib
if test $OS = "SunOS"; then
  gmake clean && gmake & gmake install
else
  make clean && make && make install
fi

cd ../communicator
aclocal
autoheader
automake --add-missing
autoconf
./configure --prefix=/tmp/jad/opendnssec --with-libksm-include=/tmp/jad/opendnssec/include --with-libksm-lib=/tmp/jad/opendnssec/lib
if test $OS = "SunOS"; then
  gmake clean && gmake & gmake install
else
  make clean && make && make install
fi

cd ../../xml
aclocal
automake --add-missing
autoconf
./configure --prefix=/tmp/jad/opendnssec -with-trang=/opt/trang.jar
if test $OS = "SunOS"; then
  gmake clean && gmake & gmake install
else
  make clean && make && make install
fi