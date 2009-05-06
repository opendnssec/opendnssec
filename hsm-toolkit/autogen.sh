#!/bin/sh
#
# $Id$

for file in AUTHORS COPYING INSTALL NEWS README; do
	test -f $file || touch $file
done

autoreconf --verbose --install --force
