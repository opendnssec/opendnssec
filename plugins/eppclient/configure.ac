# $Id: configure.ac 2881 2010-02-24 14:29:21Z jakob $

m4_sinclude([version.m4])

AC_PREREQ(2.61)
AC_INIT([opendnssec-eppclient], OPENDNSSEC_VERSION)

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
AC_REPLACE_FUNCS(strlcpy)

AC_SEARCH_LIBS(nanosleep, rt posix4, AC_DEFINE(HAVE_NANOSLEEP, 1,
	[Define if you have nanosleep]))

ACX_LIBXML2
ACX_LDNS(1,6,4)
ACX_LIBSQLITE3
LIBCURL_CHECK_CONFIG([yes], [7.18.2], [], [AC_MSG_ERROR(["libcurl not found"])])

EPPCLIENTD_CONF=$OPENDNSSEC_SYSCONF_DIR/eppclientd.conf
EPPCLIENTD_DB=$OPENDNSSEC_LOCALSTATE_DIR/eppclientd.sqlite
EPPCLIENTD_PID=$OPENDNSSEC_PID_DIR/eppclientd.pid
EPPCLIENTD_PIPE=$OPENDNSSEC_PID_DIR/eppclientd.pipe

AC_SUBST([EPPCLIENTD_CONF])
AC_SUBST([EPPCLIENTD_DB])
AC_SUBST([EPPCLIENTD_PID])
AC_SUBST([EPPCLIENTD_PIPE])

AC_DEFINE_UNQUOTED(EPPCLIENTD_CONF, "$EPPCLIENTD_CONF", [Path to the eppclientd.conf])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/eppclient.8
	src/eppclientd.8
	src/eppclientd.conf
	src/eppclientd.conf.5
])

AC_OUTPUT
