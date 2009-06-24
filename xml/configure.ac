# $Id$
#
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(opendnssec-xml, 0.0.1, jad@jadickinson.co.uk)
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

# Checks for programs.
AC_PATH_PROG(XMLLINT, xmllint)

AC_PATH_PROG(JAVA, java)

ACX_TRANG
ACX_PKCS11_MODULES

full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`

opendnsseclibexecdir=$libexecdir/opendnssec
opendnsseclocalstatedir=$localstatedir/opendnssec
opendnssecsysconfdir=$full_sysconfdir/opendnssec

AC_SUBST([opendnsseclibexecdir])
AC_SUBST([opendnsseclocalstatedir])
AC_SUBST([opendnssecsysconfdir])


AC_CONFIG_FILES([
	Makefile
	conf.xml
	zonelist.xml
])

AC_OUTPUT
