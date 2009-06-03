dnl
dnl $Id$
dnl 

define([SOFTHSM_VERSION_MAJOR], [1])
define([SOFTHSM_VERSION_MINOR], [0])
define([SOFTHSM_VERSION_FIX], [0])
define([PACKAGE_SUFFIX], [-RC2])

dnl Code changed:                      SOFTHSM_VERSION_REVISION++
dnl Interface added/removed/changed:   SOFTHSM_VERSION_CURRENT++, SOFTHSM_VERSION_REVISION=0
dnl Interface added:                   SOFTHSM_VERSION_AGE++
dnl Interface removed:                 SOFTHSM_VERSION_AGE=0
define([SOFTHSM_VERSION_CURRENT], [1])
define([SOFTHSM_VERSION_REVISION], [0])
define([SOFTHSM_VERSION_AGE], [0])




# Init 
AC_INIT([libsofthsm], [SOFTHSM_VERSION_MAJOR.SOFTHSM_VERSION_MINOR.SOFTHSM_VERSION_FIX[]PACKAGE_SUFFIX])
AC_CONFIG_SRCDIR(src/Makefile.am)

# Version info for the library
VERSION_INFO="SOFTHSM_VERSION_CURRENT:SOFTHSM_VERSION_REVISION:SOFTHSM_VERSION_AGE"
AC_SUBST(VERSION_INFO)

# Init the automake
AM_INIT_AUTOMAKE

ACX_PEDANTIC
ACX_STRICT

ACX_BOTAN
ACX_SQLITE3

AC_ARG_WITH(loglevel, [  --with-loglevel=INT     The log level. 0=No log 1=Error 2=Warning 3=Info 4=Debug (default INT=3)], [SOFTLOGLEVEL="$withval"], [SOFTLOGLEVEL=3])
AC_ARG_ENABLE(64bit, [  --enable-64bit          Compile a 64-bit version], [ENABLE64BIT="yes"], [ENABLE64BIT="no"])

# Check for compilers
AC_PROG_CC
AC_PROG_CXX
AC_CHECK_PROG(cxx_present, $CXX, "yes", "no")
if test "x$cxx_present" != "xyes"; then
    AC_MSG_ERROR([No C++ compiler found.])
fi

# Check that we can compile 64-bit before compiling
if test "$ENABLE64BIT" == "yes"
then
    org_cflags=$CFLAGS
    CFLAGS=-m64
    AC_RUN_IFELSE(
      [AC_LANG_PROGRAM([], [dnl
return sizeof(void*) == 8 ? 0 : 1;
      ])
    ],[
      CXXFLAGS="-m64 $CXXFLAGS"
      LDFLAGS="-m64 $LDFLAGS"
      CFLAGS="-m64 $org_cflags"
    ],[
    AC_MSG_ERROR([Don't know how to build a 64-bit object.])
    ])
fi

# Do not give warnings for long-long. So that we can build with newer SQLite3 
CXXFLAGS="${CXXFLAGS} -Wno-long-long"
CFLAGS="${CFLAGS} -Wno-long-long"

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
