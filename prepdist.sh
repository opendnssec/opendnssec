#!/bin/sh
#
# $Id$

PREFIX=/tmp/opendnssec-release

sh autogen.sh &&
mkdir -p build &&
cd build &&
../configure --prefix=${PREFIX} --enable-eppclient $@ &&
make dist
