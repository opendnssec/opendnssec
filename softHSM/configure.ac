dnl
dnl $Id$
dnl 

##################
#                #
#    Version     #
#                #
################

# Program version

define([SOFTHSM_VERSION_MAJOR], [1])
define([SOFTHSM_VERSION_MINOR], [0])
define([SOFTHSM_VERSION_FIX], [0])
define([PACKAGE_SUFFIX], [-RC2])

# Library version

# Code changed:                      SOFTHSM_VERSION_REVISION++
# Interface added/removed/changed:   SOFTHSM_VERSION_CURRENT++, SOFTHSM_VERSION_REVISION=0
# Interface added:                   SOFTHSM_VERSION_AGE++
# Interface removed:                 SOFTHSM_VERSION_AGE=0

define([SOFTHSM_VERSION_CURRENT], [1])
define([SOFTHSM_VERSION_REVISION], [0])
define([SOFTHSM_VERSION_AGE], [0])

##################
#                #
# Configure code #
#                #
##################

# Init 
AC_INIT([libsofthsm], [SOFTHSM_VERSION_MAJOR.SOFTHSM_VERSION_MINOR.SOFTHSM_VERSION_FIX[]PACKAGE_SUFFIX])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR(src/Makefile.am)
AC_CONFIG_MACRO_DIR([m4])

# Version info for the library
VERSION_INFO="SOFTHSM_VERSION_CURRENT:SOFTHSM_VERSION_REVISION:SOFTHSM_VERSION_AGE"
AC_SUBST(VERSION_INFO)

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX

ACX_PEDANTIC
ACX_STRICT

# Do not give warnings for long-long. So that we can build with newer SQLite3 
CPPFLAGS="${CPPFLAGS} -Wno-long-long"

# Configure arguments
AC_ARG_WITH(
        [loglevel],
        [AS_HELP_STRING([--with-loglevel=INT],[The log level. 0=No log 1=Error 2=Warning 3=Info 4=Debug (default INT=3)])],
        [SOFTLOGLEVEL="$withval"],
        [SOFTLOGLEVEL=3]
)
AC_ARG_ENABLE(
        [64bit],
        [AS_HELP_STRING([--enable-64bit],[enable 64-bit compiling])],
        [enable_64bit="yes"],
        [enable_64bit="no"]
)
if test "x$enable_64bit" = "xyes"
then
        AC_MSG_CHECKING(if we can compile in 64-bit mode)
        tmp_CFLAGS=$CFLAGS
        CFLAGS=-m64
        AC_RUN_IFELSE(
                [
                        AC_LANG_PROGRAM(
                                [],
                                [return sizeof(void*) == 8 ? 0 : 1;]
                        )
                ],
                [
                        AC_MSG_RESULT(yes)
                        CXXFLAGS="-m64 $CXXFLAGS"
                        LDFLAGS="-m64 $LDFLAGS"
                        CFLAGS="-m64 $tmp_CFLAGS"
                ],
                [
                        AC_MSG_RESULT(no)
                        AC_MSG_ERROR([Don't know how to compile in 64-bit mode.])
                ]
        )
fi

# Check for library include arguments
ACX_BOTAN
ACX_SQLITE3

AC_CHECK_FUNCS(getpassphrase)
AC_CHECK_HEADERS([sys/time.h dlfcn.h], [], [],
  [[#ifdef HAVE_DLFCN_H
  #include <dlfcn.h>
  #endif
  ]])

# Define some variables for the code
AC_DEFINE_UNQUOTED(VERSION_MAJOR, SOFTHSM_VERSION_MAJOR)
AC_DEFINE_UNQUOTED(VERSION_MINOR, SOFTHSM_VERSION_MINOR)
AC_DEFINE_UNQUOTED(SOFTLOGLEVEL, $SOFTLOGLEVEL)
AC_DEFINE_UNQUOTED(MAX_SESSION_COUNT, 2048)

# Generate the libtool script and install script 
AC_PROG_LIBTOOL 
AC_PROG_INSTALL

# Generate the make files
AC_OUTPUT(Makefile src/Makefile src/lib/Makefile src/bin/Makefile checks/Makefile)
