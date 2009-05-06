# $Id$

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(communicator, 0.0.1, jad@jadickinson.co.uk)
AM_INIT_AUTOMAKE
AC_PROG_MAKE_SET
AC_CONFIG_SRCDIR([src/daemon.h])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h inttypes.h stdlib.h string.h syslog.h unistd.h stdio.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_CHECK_FUNCS([dup2 endpwent select strerror strtol])

# Check for libksm
AC_ARG_WITH(libksm-include,
[  --with-libksm-include=DIR     Look for libksm headers in this dir ],
   KSM_INCLUDES="$withval"
)
AC_ARG_WITH(libksm-lib,
[  --with-libksm-lib=DIR     Look for libksm libs in this dir ],
   KSM_LIBS="$withval"
)
AC_MSG_CHECKING(what is the libksm include path)
if test "x$KSM_INCLUDES" = "x"; then
  KSM_INCLUDES="/usr/local/include"
fi
AC_MSG_RESULT($KSM_INCLUDES)
AC_MSG_CHECKING(what is the libksm libs path)
if test "x$KSM_LIBS" = "x"; then
  KSM_LIBS="/usr/local/lib"
fi
AC_MSG_RESULT($KSM_LIBS)
AC_SUBST(KSM_INCLUDES)
AC_SUBST(KSM_LIBS)

AC_CONFIG_FILES([
Makefile
src/Makefile
])
AC_OUTPUT
