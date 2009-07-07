#!/bin/sh
#
# $Id$

ACLOCAL="aclocal -I ../m4"
export ACLOCAL

autoreconf --install --force
