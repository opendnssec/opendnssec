#!/bin/sh
#
# $Id: prepdist.sh 5634 2011-09-13 15:20:29Z jerry $

PREFIX=/var/tmp/opendnssec-release

sh autogen.sh &&
sh configure --prefix=${PREFIX} $@ &&
make dist
