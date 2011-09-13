#!/bin/sh
#
# $Id$

PREFIX=/var/tmp/opendnssec-release

sh autogen.sh
sh configure \
	--prefix=${PREFIX} \
	--enable-eppclient \
	--enable-auditor $@
make dist
