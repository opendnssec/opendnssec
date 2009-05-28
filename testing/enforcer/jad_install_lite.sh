#!/bin/sh

MYDIR=/tmp/jad/opendnssec
mkdir -p $MYDIR
cd $MYDIR

echo "installing in $MYDIR/install"

# clean out old builds
rm -rf build-* install

# co/up src
if test -d /tmp/jad/opendnssec/trunk; then
  cd trunk
  svn up
else
  svn co svn+ssh://keihatsu.kirei.se/svn/dnssec/trunk
  cd trunk
fi

#Build automagic stuuff
echo "libksm automagic"
cd libksm
sh autogen.sh
echo "softHSM automagic"
cd ../softHSM
sh autogen.sh
echo "libhsm automagic"
cd ../libhsm
sh autogen.sh
echo "enforcer automagic"
cd ../enforcer
sh autogen.sh
echo "xml automagic"
cd ../xml
sh autogen.sh

# build
echo "***************** LIBKSM"
mkdir $MYDIR/build-ksm
cd $MYDIR/build-ksm
OS=`uname -s`
if test $OS = "Darwin"; then
echo "Building for $OS"
../trunk/libksm/configure --prefix=$MYDIR/install 
fi
if [ $OS = "Linux" ]; then
echo "Building for $OS"
../trunk/libksm/configure --prefix=$MYDIR/install
fi
if test $OS = "FreeBSD"; then
echo "Building for $OS"
../trunk/libksm/configure --prefix=$MYDIR/install
fi
if test $OS = "SunOS"; then
echo "Building for $OS"
../trunk/libksm/configure --prefix=$MYDIR/install
fi
if test $OS = "SunOS"; then
  gmake clean && gmake & gmake install
else
  make clean && make -j8 && make install
fi

echo "***************** SoftHSM"
cd ..
mkdir $MYDIR/build-softhsm
cd $MYDIR/build-softhsm
../trunk/softHSM/configure --prefix=$MYDIR/install --with-botan=/opt/botan
if test $OS = "SunOS"; then
  gmake clean && gmake & gmake install
else
  make clean && make -j8 && make install
fi

echo "***************** LIBHSM"
cd ..
mkdir $MYDIR/build-hsm
cd $MYDIR/build-hsm
../trunk/libhsm/configure --prefix=$MYDIR/install --with-ldns=/opt/ldns-1.4.0
if test $OS = "SunOS"; then
  gmake clean && gmake & gmake install
else
  make clean && make  && make install
fi

echo "***************** Enforcer"
cd ..
mkdir $MYDIR/build-enforcer
cd $MYDIR/build-enforcer
../trunk/enforcer/configure --prefix=$MYDIR/install --with-libksm=$MYDIR/install --with-libhsm=$MYDIR/install
if test $OS = "SunOS"; then
  gmake clean && gmake & gmake install
else
  make clean && make -j8 && make install
fi

echo "***************** XML"
cd ..
mkdir $MYDIR/build-xml
cd $MYDIR/build-xml
../trunk/xml/configure --prefix=$MYDIR/install -with-trang=/opt/trang.jar
if test $OS = "SunOS"; then
  gmake clean && gmake & gmake install
else
  make clean && make -j8 && make install
fi

