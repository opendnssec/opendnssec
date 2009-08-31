# $Id$

AC_PREREQ(2.61)
AC_INIT([opendnssec-xml],[0.0.3],[jad@jadickinson.co.uk])

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

# Checks for programs.
AC_PATH_PROG(XMLLINT, xmllint)
AC_PATH_PROG(JAVA, java)

ACX_PKCS11_MODULES

full_localstatedir=`eval eval eval eval eval echo "${localstatedir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`

opendnsseclocalstatedir=$full_localstatedir/opendnssec
opendnssecsysconfdir=$full_sysconfdir/opendnssec

AC_SUBST([opendnsseclocalstatedir])
AC_SUBST([opendnssecsysconfdir])


AC_CONFIG_FILES([
	Makefile
	conf.xml
	kasp.xml
	signconf.xml
	zonelist.xml
])

AC_OUTPUT
