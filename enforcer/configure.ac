# $Id: configure.ac 615 2009-05-06 08:52:03Z jakob $

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(enforcer, 0.0.1, jad@jadickinson.co.uk)
AM_INIT_AUTOMAKE
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_CONFIG_SRCDIR([common/daemon.h])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

AC_ARG_ENABLE(
	[strict],
	[AS_HELP_STRING([--enable-strict],[enable strict compile mode @<:@enabled@:>@])],
	,
	[enable_strict="yes"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AS_HELP_STRING([--enable-pedantic],[enable pedantic compile mode @<:@enabled@:>@])],
	,
	[enable_pedantic="yes"]
)

# Checks for libraries.
AC_SEARCH_LIBS(uuid_generate, uuid)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h inttypes.h stdlib.h string.h syslog.h unistd.h stdio.h])
AC_HEADER_TIME

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
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES

# Check for libksm
AC_ARG_WITH(libksm,
[  --with-libksm=DIR     Look for libksm in this dir ],
   [LIBKSM="$withval"
    CFLAGS="$CFLAGS -I$withval/include"
    CPPFLAGS="$CPPFLAGS -I$withval/include"
		LDFLAGS="-L$withval/lib $LDFLAGS"]
)

AC_CHECK_HEADERS(ksm/ksm.h,, [
		AC_MSG_ERROR([Can't find libksm headers])
	]
)
AC_CHECK_LIB(ksm,KsmInit,, [
		AC_MSG_ERROR([Can't find libksm library])
	]
)

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
keygend_conf_schema=$sysconfdir/opendnssec/conf.rng
AC_DEFINE_UNQUOTED(CONFIGRNG, ["`eval echo $keygend_conf_schema`"], [Path to the OpenDNSSEC configuration schema file])
com_pid_file=$localstatedir/run/opendnssec/communicated.pid
AC_DEFINE_UNQUOTED(COM_PID, ["`eval echo $com_pid_file`"], [Path to the OpenDNSSEC communicated pid file])
keygen_pid_file=$localstatedir/run/opendnssec/keygend.pid
AC_DEFINE_UNQUOTED(KEYGEN_PID, ["`eval echo $keygen_pid_file`"], [Path to the OpenDNSSEC keygend pid file])

signer_conf_dir=$localstatedir/opendnssec/config
AC_DEFINE_UNQUOTED(SIGNER_CONF_DIR, ["`eval echo $signer_conf_dir`"], [Path to the OpenDNSSEC signer configuration directory])

CPPFLAGS="${CPPFLAGS} ${XML_INCLUDES}"

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes";
	CFLAGS="${CFLAGS} -pedantic"
fi
if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wextra"
fi

AC_CONFIG_FILES([
Makefile
common/Makefile
communicated/Makefile
keygend/Makefile
])
AC_OUTPUT
