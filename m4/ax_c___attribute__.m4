dnl @synopsis AX_C___ATTRIBUTE__
dnl
dnl Provides a test for the compiler support of __attribute__
dnl extensions. defines HAVE___ATTRIBUTE__ if it is found.
dnl
dnl Originating from the 'pork' package by Ryan McCabe <ryan@numb.org>
dnl
dnl @category C
dnl @author Christian Haggstrom <chm@c00.info>
dnl @version 2005-01-21
dnl @license GPLWithACException

# 2007-07-23 Stepan Kasal <skasal@redhat.com>
#	- fix for gcc4, use "ax_cv_" prefix, avoid obsolete AC_TRY_COMPILE

AC_DEFUN([AX_C___ATTRIBUTE__], [
  AC_CACHE_CHECK([for __attribute__], [ax_cv___attribute__],
    [AC_COMPILE_IFELSE(
      [AC_LANG_PROGRAM(
	[[#include <stdlib.h>
	  static void foo(void) __attribute__ ((unused));
	  static void
	  foo(void) {
	      exit(1);
	  }
        ]], [])],
      [ax_cv___attribute__=yes],
      [ax_cv___attribute__=no]
    )
  ])
  if test "$ax_cv___attribute__" = "yes"; then
    AC_DEFINE([HAVE___ATTRIBUTE__], 1, [define if your compiler has __attribute__])
  fi
])
