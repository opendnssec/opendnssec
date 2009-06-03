# $Id: configure.ac 615 2009-05-06 08:52:03Z jakob $

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(enforcer, 0.0.1, jad@jadickinson.co.uk)
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_CONFIG_SRCDIR([common/daemon.h])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

ACX_PEDANTIC
ACX_STRICT

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

ACX_LIBXML2
ACX_LIBHSM
ACX_LIBKSM

AC_SUBST(RUNTIME_PATH)

keygend_conf_file=$sysconfdir/opendnssec/conf.xml
AC_DEFINE_UNQUOTED(CONFIGFILE, ["`eval echo $keygend_conf_file | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC configuration file])
keygend_conf_schema=$sysconfdir/opendnssec/conf.rng
AC_DEFINE_UNQUOTED(CONFIGRNG, ["`eval echo $keygend_conf_schema  | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC configuration schema file])
com_pid_file=$localstatedir/run/opendnssec/communicated.pid
AC_DEFINE_UNQUOTED(COM_PID, ["`eval echo $com_pid_file | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC communicated pid file])
keygen_pid_file=$localstatedir/run/opendnssec/keygend.pid
AC_DEFINE_UNQUOTED(KEYGEN_PID, ["`eval echo $keygen_pid_file | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC keygend pid file])

signer_conf_dir=$localstatedir/opendnssec/config
AC_DEFINE_UNQUOTED(SIGNER_CONF_DIR, ["`eval echo $signer_conf_dir | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC signer configuration directory])

AC_CONFIG_FILES([
Makefile
common/Makefile
communicated/Makefile
keygend/Makefile
])
AC_OUTPUT
