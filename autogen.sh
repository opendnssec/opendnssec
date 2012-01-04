#!/bin/sh
#
# $Id$

VERSION=version.m4

if [ `dirname $0` = ".." ]; then
	if [ -f ../${VERSION} ]; then
		echo Creating ${VERSION} &&
		rm -f ${VERSION} &&
		ln ../${VERSION} ${VERSION}
	fi
fi &&

echo "Running autoreconf" &&
autoreconf --install --force
