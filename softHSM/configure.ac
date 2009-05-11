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

# Strict
AC_ARG_ENABLE(
	[strict],
	[AS_HELP_STRING([--enable-strict],[enable strict compile mode @<:@enabled@:>@])],
	,
	[enable_strict="yes"]
)

# Pedantic
AC_ARG_ENABLE(
	[pedantic],
	[AS_HELP_STRING([--enable-pedantic],[enable pedantic compile mode @<:@enabled@:>@])],
	,
	[enable_pedantic="yes"]
)

AC_ARG_WITH(botan-lib, [  --with-botan-lib=DIR    The location of the Botan crypto library (default DIR=/usr/local/lib)], [BOTANLIBDIR="$withval"], [BOTANLIBDIR="/usr/local/lib"])
AC_ARG_WITH(botan-inc, [  --with-botan-inc=DIR    The location of the Botan crypto library include files (default DIR=/usr/local/include)], [BOTANINCDIR="$withval"], [BOTANINCDIR="/usr/local/include"])
AC_ARG_WITH(sqlite3-lib, [  --with-sqlite3-lib=DIR  The location of the SQLite3 library (default DIR=/usr/lib)], [SQLITELIBDIR="$withval"], [SQLITELIBDIR="/usr/lib"])
AC_ARG_WITH(sqlite3-inc, [  --with-sqlite3-inc=DIR  The location of the SQLite3 library include files (default DIR=/usr/include)], [SQLITEINCDIR="$withval"], [SQLITEINCDIR="/usr/include"])
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

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes";
	CFLAGS="${CFLAGS} -pedantic"
	CXXFLAGS="${CXXFLAGS} -pedantic"
fi

if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wextra"
	CXXFLAGS="${CXXFLAGS} -Wall -Wextra"
fi

# Configure the path to Botan and SQLite3
LDFLAGS="$LDFLAGS -L$BOTANLIBDIR -R$BOTANLIBDIR -L$SQLITELIBDIR -R$SQLITELIBDIR"
CXXFLAGS="$CXXFLAGS -I$BOTANINCDIR -I$SQLITEINCDIR"
CFLAGS="$CFLAGS -I$BOTANINCDIR -I$SQLITEINCDIR"

# Check that we have headers and SQLite library
AC_CHECK_FUNCS(getpassphrase)
AC_CHECK_HEADERS([sys/time.h sqlite3.h])
AC_CHECK_LIB(sqlite3, sqlite3_prepare_v2, [], [AC_MSG_ERROR([Missing SQLite3 library v3.4.2 or greater])])

# Check that we have Botan
LIBS="$LIBS -lbotan"
AC_LANG(C++)
AC_LINK_IFELSE(
	[AC_LANG_PROGRAM([#include <botan/init.h>
			  #include <botan/pipe.h>
			  #include <botan/filters.h>
			  #include <botan/hex.h>
			  #include <botan/sha2_32.h>
			  #include <botan/emsa3.h>],
			 [using namespace Botan;
                          LibraryInitializer::initialize();
			  new EMSA3_Raw();])],
	[AC_MSG_RESULT([checking for Botan library v1.7.24 or greater... yes])],
	[AC_MSG_RESULT([checking for Botan library v1.7.24 or greater... no])
         AC_MSG_ERROR([Missing Botan library v1.7.24 or greater])]
)

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
