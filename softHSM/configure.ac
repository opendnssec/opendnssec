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
AC_PREREQ(2.61)
AC_INIT([libsofthsm],[SOFTHSM_VERSION_MAJOR.SOFTHSM_VERSION_MINOR.SOFTHSM_VERSION_FIX[]PACKAGE_SUFFIX],[rickard.bondesson@iis.se])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([src/Makefile.am])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

# Version info for the library
VERSION_INFO="SOFTHSM_VERSION_CURRENT:SOFTHSM_VERSION_REVISION:SOFTHSM_VERSION_AGE"
AC_SUBST(VERSION_INFO)

# Checks for compilers
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

ACX_64BIT

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
AC_DEFINE_UNQUOTED(
  [VERSION_MAJOR],
  [SOFTHSM_VERSION_MAJOR],
  [SoftHSM version number via PKCS#11]
)
AC_DEFINE_UNQUOTED(
  [VERSION_MINOR],
  [SOFTHSM_VERSION_MINOR],
  [SoftHSM version number via PKCS#11]
)
AC_DEFINE_UNQUOTED(
  [SOFTLOGLEVEL],
  [$SOFTLOGLEVEL],
  [The log level set by the user]
)
AC_DEFINE_UNQUOTED(
  [MAX_SESSION_COUNT],
  [2048],
  [Maximum number of concurrent sessions]
)
AC_DEFINE_UNQUOTED(
  [MAX_PIN_LEN],
  [255],
  [Maximum PIN length]
)
AC_DEFINE_UNQUOTED(
  [MIN_PIN_LEN],
  [4],
  [Minimum PIN length]
)
AC_DEFINE_UNQUOTED(
  [DEFAULT_SOFTHSM_CONF],
  ["`eval echo ${sysconfdir} | sed s,NONE,$ac_default_prefix,g`/softhsm.conf"],
  [The default location of softhsm.conf]
)

# Generate the libtool script and install script 
LT_INIT 
AC_PROG_INSTALL

softhsmdbdir=${localstatedir}/softhsm
AC_SUBST([softhsmdbdir])

# Generate the make files
AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/lib/Makefile
	src/bin/Makefile
	checks/Makefile
	softhsm.conf
])

AC_OUTPUT
