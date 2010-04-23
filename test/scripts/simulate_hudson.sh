#!/bin/sh
#
# $Id$

WORKSPACE=${HOME}/tmp/workspace
export WORKSPACE

rm -fr WORKSPACE
mkdir -p $WORKSPACE

cd $WORKSPACE
svn export http://svn.opendnssec.org/trunk/OpenDNSSEC src

sh -vx src/test/scripts/build_and_test.sh
