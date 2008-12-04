dnl
dnl $Id$
dnl 

AC_INIT([libsofthsm.so], [1.0.0])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR(src/main.cpp)

VERSION_INFO="1:0:0"
AC_SUBST(VERSION_INFO)

AM_INIT_AUTOMAKE

AC_ARG_WITH(botan, [  --with-botan=DIR        The location of the Botan crypto library (default /usr/local/lib)], [BOTANDIR="$withval"], [BOTANDIR="/usr/local/lib"])
AC_SUBST(BOTANDIR)

AC_PROG_CXX
AC_PROG_LIBTOOL

AC_OUTPUT(Makefile src/Makefile)
