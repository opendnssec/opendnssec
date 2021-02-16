#!/bin/sh
#
VERSION=version.m4

if [ `dirname $0` = ".." ]; then
	if [ -f ../${VERSION} ]; then
		echo Creating ${VERSION} &&
		rm -f ${VERSION} &&
		ln ../${VERSION} ${VERSION} 2>/dev/null ||
		ln -s ../${VERSION} ${VERSION} 2>/dev/null ||
		cp ../${VERSION} ${VERSION}
	fi
fi &&

case `uname` in Darwin*) glibtoolize --copy ;;
  *) libtoolize --copy ;; esac

aclocal -I m4 --install
autoheader
autoconf
automake --foreign --add-missing --force-missing --copy
