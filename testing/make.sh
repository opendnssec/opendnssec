#!/usr/bin/env bash

set -e 

if [ -n "$INSTALL_TAG" -a -z "$INSTALL_ROOT" ]; then
  INSTALL_ROOT="$WORKSPACE_ROOT/root/$INSTALL_TAG"
fi

if [ \! -f $INSTALL_ROOT/.botan.ok ] ; then
  rm -f Botan-1.10.10.tgz
  wget 'http://botan.randombit.net/releases/Botan-1.10.10.tgz'
  gzip -d < Botan-1.10.10.tgz | tar xf -
  cd Botan-1.10.10
  ./configure.py --prefix="$INSTALL_ROOT"
  make
  make install
  cd ..
  touch $INSTALL_ROOT/.botan.ok
  echo "1.10.10" > $INSTALL_ROOT/.botan.build
fi

if [ \! -f $INSTALL_ROOT/.softhsm2.ok ] ; then
  rm -f softhsm-2.0.0.tar.gz
  wget 'https://dist.opendnssec.org/source/softhsm-2.0.0.tar.gz'
  gzip -d < softhsm-2.0.0.tar.gz | tar xf -
  cd softhsm-2.0.0
  ./configure --prefix="$INSTALL_ROOT" \
              --disable-non-paged-memory \
              --with-migrate \
              --with-crypto-backend=botan \
              --with-botan="$INSTALL_ROOT"
  make
  make install
  cp "src/lib/common/softhsm2.conf" "$INSTALL_ROOT/etc/softhsm2.conf.build"
  touch $INSTALL_ROOT/.softhsm2.ok
  echo "2.0.0" > $INSTALL_ROOT/.softhsm2.build
fi

exit 0
