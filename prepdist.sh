#!/bin/sh
#
# $Id: prepdist.sh 5999 2012-01-04 14:45:36Z jakob $

PREFIX=/tmp/opendnssec-release

sh autogen.sh &&
mkdir -p build &&
cd build &&
../configure --prefix=${PREFIX} --enable-eppclient $@ &&
make dist
