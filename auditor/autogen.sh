#!/bin/sh
#
# $Id$

if [ -d m4 ]; then
	ACLOCAL="aclocal -Im4"
	export ACLOCAL
fi

autoreconf --install --force
