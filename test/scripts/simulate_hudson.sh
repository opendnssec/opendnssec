#!/bin/sh
#
# $Id$

WORKSPACE=${HOME}/tmp/workspace
export WORKSPACE

rm -fr WORKSPACE
mkdir -p $WORKSPACE

cd $WORKSPACe
svn export http://svn.opendnssec.org/trunk/OpenDNSSEC OpenDNSSEC

cd $WORKSPACE/OpenDNSSEC
sh -vx test/scripts/build_and_test.sh
