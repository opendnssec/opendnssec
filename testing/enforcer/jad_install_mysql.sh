#!/bin/sh

MYDIR=/tmp/jad/opendnssec
mkdir -p $MYDIR
cd $MYDIR

echo "installing in $MYDIR/install"

# clean out old builds
rm -rf build install
mkdir build

# co/up src
if test -d /tmp/jad/opendnssec/trunk; then
  cd trunk
  svn up
else
  svn co svn+ssh://keihatsu.kirei.se/svn/dnssec/trunk
  cd trunk
fi

#Build automagic stuuff
cd libksm
sh autogen.sh
cd ../enforcer
sh autogen.sh
cd ../xml
sh autogen.sh

# build
cd $MYDIR/build
OS=`uname -s`
if test $OS = "Darwin"; then
echo "Building for $OS"
../trunk/libksm/configure --prefix=$MYDIR/install --with-mysql=/usr/local/mysql --with-cunit=/usr/local --with-dbname=test --with-dbhost=test1 --with-dbpass="" --with-dbuser=root
fi
if [ $OS = "Linux" ]; then
echo "Building for $OS"
../trunk/libksm/configure --prefix=$MYDIR/install --with-mysql=/usr --with-cunit=/usr --with-dbname=ksm --with-dbhost=localhost --with-dbpass=ksm_test --with-dbuser=ksm_test
fi
if test $OS = "FreeBSD"; then
echo "Building for $OS"
../trunk/libksm/configure --prefix=$MYDIR/install --with-mysql=/usr/local --with-cunit=/usr/local --with-dbname=test --with-dbhost=test1 --with-dbpass="" --with-dbuser=root
fi
if test $OS = "SunOS"; then
echo "Building for $OS"
../trunk/libksm/configure --prefix=$MYDIR/install --with-mysql=/usr/sfw
fi
if test $OS = "SunOS"; then
  gmake clean && gmake & gmake install
else
  make clean && make -j8 && make install
fi

../trunk/enforcer/configure --prefix=$MYDIR/install --with-libksm-include=$MYDIR/install/include --with-libksm-lib=$MYDIR/install/lib
if test $OS = "SunOS"; then
  gmake clean && gmake & gmake install
else
  make clean && make -j8 && make install
fi

../trunk/xml/configure --prefix=$MYDIR/install -with-trang=/opt/trang.jar
if test $OS = "SunOS"; then
  gmake clean && gmake & gmake install
else
  make clean && make -j8 && make install
fi

