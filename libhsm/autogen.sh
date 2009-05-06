#!/bin/sh
#
# $Id$

for file in AUTHORS COPYING INSTALL NEWS README ChangeLog; do
	test -f $file || touch $file
done

autoreconf --install --force
