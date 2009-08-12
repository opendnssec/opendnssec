# $Id$

AC_PREREQ(2.61)
AC_INIT([hsmbully], [0.0.1], [rick@openfortress.nl])

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

AC_CONFIG_SRCDIR([src/hsmbully.c])
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
AC_CHECK_HEADERS([stdlib.h stdio.h math.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC

ACX_CUNIT
ACX_DLOPEN

AC_CONFIG_FILES([
Makefile
src/Makefile
])

AC_OUTPUT
