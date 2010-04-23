#!/bin/sh
#
# $Id$

WORKSPACE=${HOME}/tmp/workspace
export WORKSPACE

mkdir -p $WORKSPACE

cd $WORKSPACE
svn co http://svn.opendnssec.org/trunk/OpenDNSSEC OpenDNSSEC

sh `dirname $0`/build_and_test.sh
