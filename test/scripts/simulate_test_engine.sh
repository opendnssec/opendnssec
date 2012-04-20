#!/bin/sh
#
# $Id$

WORKSPACE=${HOME}/tmp/workspace
export WORKSPACE

SCRIPTS=`pwd`

rm -fr $WORKSPACE
mkdir -p $WORKSPACE

cd $WORKSPACE
svn export http://svn.opendnssec.org/trunk/OpenDNSSEC src

if [ "$1" = "--local" ]; then
	sh -vx $SCRIPTS/build_and_test.sh
else
	sh -vx src/test/scripts/build_and_test.sh
fi
