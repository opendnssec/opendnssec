#!/bin/sh
#
# $Id$

find . -type d -name '.svn' -prune -o -type d -print |\
xargs svn propset -F `dirname $0`/svnignore.txt svn:ignore 
