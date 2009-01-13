dnl
dnl $Id$
dnl 

AC_INIT([libsofthsm.so], [1.0.0])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR(src/main.cpp)

VERSION_INFO="1:0:0"
AC_SUBST(VERSION_INFO)

AM_INIT_AUTOMAKE
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_PROG_INSTALL

AC_ARG_WITH(botan-lib, [  --with-botan-lib=DIR    The location of the Botan crypto library (default DIR=/usr/local/lib)], [BOTANLIBDIR="$withval"], [BOTANLIBDIR="/usr/local/lib"])
AC_ARG_WITH(botan-inc, [  --with-botan-inc=DIR    The location of the Botan crypto library include files (default DIR=/usr/local/include)], [BOTANINCDIR="$withval"], [BOTANINCDIR="/usr/local/include"])
AC_ARG_WITH(sqlite3-lib, [  --with-sqlite3-lib=DIR  The location of the SQLite3 library (default DIR=/usr/lib)], [SQLITELIBDIR="$withval"], [SQLITELIBDIR="/usr/lib"])
AC_ARG_WITH(sqlite3-inc, [  --with-sqlite3-inc=DIR  The location of the SQLite3 library include files (default DIR=/usr/include)], [SQLITEINCDIR="$withval"], [SQLITEINCDIR="/usr/include"])
AC_ARG_ENABLE(64bit, [  --enable-64bit          Compile a 64-bit version], [ENABLE64BIT="yes"], [ENABLE64BIT="no"])

if test "$ENABLE64BIT" = "yes"; then
  CXXFLAGS="-m64 $CXXFLAGS"
  CFLAGS="-m64 $CFLAGS"
  LDFLAGS="-m64 $LDFLAGS"
fi

LDFLAGS="$LDFLAGS -L$BOTANLIBDIR -R$BOTANLIBDIR -L$SQLITELIBDIR -R$SQLITELIBDIR"
CXXFLAGS="$CXXFLAGS -I$BOTANINCDIR -I$SQLITEINCDIR"
CFLAGS="$CFLAGS -I$BOTANINCDIR -I$SQLITEINCDIR"

AC_CHECK_HEADER(sqlite3.h, AC_CHECK_LIB(sqlite3, sqlite3_open, [], [AC_MSG_ERROR([Missing SQLite3 library])]), [AC_MSG_ERROR([Missing SQLite3 header])])
dnl AC_CHECK_LIB(botan, Botan::BigInt, [], [AC_MSG_ERROR([Missing Botan library])])
LDFLAGS="$LDFLAGS -lbotan"

AC_OUTPUT(Makefile src/Makefile)
