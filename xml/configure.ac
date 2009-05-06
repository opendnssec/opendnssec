# $Id$
#
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(OpenDNSSEC Example, 0.0.1, jad@jadickinson.co.uk)
AM_INIT_AUTOMAKE
# Checks for programs.
AC_PATH_PROG(XMLLINT, xmllint)

AC_PATH_PROG(JAVA, java)
AC_ARG_WITH(trang,
[  --with-trang=PATH     Path to trang.jar ],
   TRANGJAR="$withval"
)
if test "x$TRANGJAR" != "x"
then
  if test -e $TRANGJAR
  then
    TRANG="$JAVA -jar $TRANGJAR"
    AC_MSG_NOTICE(trang will run like this $TRANG)
  else
    AC_MSG_ERROR(trang.jar is needed to continue. Say where it is with --with-trang=PATH)
  fi
else
  AC_MSG_ERROR(trang.jar is needed to continue. Say where it is with --with-trang=PATH)
fi


# Checks for libraries.

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES([
Makefile
])

AC_OUTPUT
