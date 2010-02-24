# $Id$

m4_sinclude([version.m4])

AC_PREREQ(2.61)
AC_INIT([opendnssec-conf], OPENDNSSEC_VERSION)

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

OPENDNSSEC_COMMON

# Checks for programs.
AC_PATH_PROG(XMLLINT, xmllint)
AC_PATH_PROG(XSLTPROC, xsltproc)
AC_PATH_PROG(JAVA, java)

ACX_PKCS11_MODULES

AC_CONFIG_FILES([
	Makefile
	conf.xml
	kasp.xml
	signconf.xml
	zonelist.xml
	zonefetch.xml
])

AC_OUTPUT
