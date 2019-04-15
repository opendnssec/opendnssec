#!/usr/bin/env bash

set -e 

if [ -n "$INSTALL_TAG" -a -z "$INSTALL_ROOT" ]; then
  INSTALL_ROOT="$WORKSPACE_ROOT/root/$INSTALL_TAG"
fi

if [ \! -f $INSTALL_ROOT/.softhsm2.ok ] ; then
  rm -f softhsm-2.*.tar.gz
  wget 'https://dist.opendnssec.org/source/softhsm-2.5.0.tar.gz'
  gzip -d < softhsm-2.5.0.tar.gz | tar xf -
  cd softhsm-2.5.0
  ./configure --prefix="$INSTALL_ROOT" \
              --disable-non-paged-memory \
              --with-migrate --disable-p11-kit \
              --with-crypto-backend=openssl \
              --disable-ecc --disable-gost
  make
  make install
  cp "src/lib/common/softhsm2.conf" "$INSTALL_ROOT/etc/softhsm2.conf.build"
  touch $INSTALL_ROOT/.softhsm2.ok
  echo "2.5.0" > $INSTALL_ROOT/.softhsm2.build
fi

exit 0
