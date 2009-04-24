#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(keygend, 0.0.1, jad@jadickinson.co.uk)
AM_INIT_AUTOMAKE
AC_PROG_MAKE_SET
AC_CONFIG_SRCDIR([src/daemon.h])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h inttypes.h stdlib.h string.h syslog.h unistd.h])

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

AC_ARG_WITH(libxml2,
[  --with-libxml2=DIR     Look for libxml2 in this dir ],
  [ XML_PATH="$withval"]
)
  if test "x$XML_PATH" = "x"; then
     AC_PATH_PROGS(XML_CONFIG, xml2-config, xml2-config, $PATH)
  else
     AC_PATH_PROGS(XML_CONFIG, xml2-config, xml2-config, $XML_PATH/bin)
  fi
  if test -x "$XML_CONFIG"
  then
     AC_MSG_CHECKING(what are the libxml2 includes)
     XML_INCLUDES="`$XML_CONFIG --cflags`"
     AC_MSG_RESULT($XML_INCLUDES)
     AC_MSG_CHECKING(what are the libxml2 libs)
     XML_LIBS="`$XML_CONFIG --libs`"
     AC_MSG_RESULT($XML_LIBS)
  fi

AC_SUBST(XML_INCLUDES)
AC_SUBST(XML_LIBS)

keygend_conf_file=$sysconfdir/opendnssec/conf.xml
AC_DEFINE_UNQUOTED(CONFIGFILE, ["`eval echo $keygend_conf_file`"], [Path to the OpenDNSSEC configuration file])

AC_CONFIG_FILES([
Makefile
src/Makefile
])
AC_OUTPUT
