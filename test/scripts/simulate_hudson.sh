#!/bin/sh
#
# $Id$

WORKSPACE=${HOME}/tmp/workspace
export WORKSPACE

mkdir -p $WORKSPACE

cd $WORKSPACE
svn export http://svn.opendnssec.org/trunk/OpenDNSSEC OpenDNSSEC

cd $WORKSPACE/OpenDNSSEC
sh `dirname $0`/build_and_test.sh
