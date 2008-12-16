dnl
dnl $Id$
dnl 

AC_INIT([libsofthsm.so], [1.0.0])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR(src/main.cpp)

VERSION_INFO="1:0:0"
AC_SUBST(VERSION_INFO)

AM_INIT_AUTOMAKE

AC_ARG_WITH(botan, [  --with-botan=DIR        The location of the Botan crypto library (default DIR=/usr/local/lib)], [BOTANDIR="$withval"], [BOTANDIR="/usr/local/lib"])
AC_SUBST(BOTANDIR)
AC_ARG_WITH(sqlite3, [  --with-sqlite3=DIR      The location of the SQLite3 library (default DIR=/usr/lib)], [SQLITEDIR="$withval"], [SQLITEDIR="/usr/lib"])
AC_SUBST(SQLITEDIR)
AC_ARG_ENABLE(64bit, [  --enable-64bit          Compile a 64-bit version], [ENABLE64BIT="yes"], [ENABLE64BIT="no"])

if test "$ENABLE64BIT" = "yes"; then
  CXXFLAGS="-m64 $CXXFLAGS"
  CFLAGS="-m64 $CFLAGS"
  LDFLAGS="-m64 $LDFLAGS"
fi

AC_PROG_CXX
AC_PROG_LIBTOOL

AC_OUTPUT(Makefile src/Makefile)
