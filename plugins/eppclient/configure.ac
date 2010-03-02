# $Id: configure.ac 2881 2010-02-24 14:29:21Z jakob $

m4_sinclude([version.m4])

define([EPPCLIENT_VERSION], [0.0])

AC_PREREQ(2.61)
AC_INIT([opendnssec-eppclient], EPPCLIENT_VERSION)

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

OPENDNSSEC_COMMON

AC_CONFIG_SRCDIR([src/eppclient.c])
AC_CONFIG_HEADER([config.h])

AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

ACX_PEDANTIC
ACX_STRICT
 
# Checks for header files.
AC_HEADER_STDC
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_VPRINTF
#AC_REPLACE_FUNCS(strlcpy)
#AC_REPLACE_FUNCS(strlcat)

AC_SEARCH_LIBS(nanosleep, rt posix4, AC_DEFINE(HAVE_NANOSLEEP, 1,
	[Define if you have nanosleep]))

ACX_LIBXML2
ACX_LDNS(1,6,4)
ACX_LIBSQLITE3
ACX_LIBCURL

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])

AC_OUTPUT
