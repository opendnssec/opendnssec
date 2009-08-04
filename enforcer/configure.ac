# $Id$

AC_PREREQ(2.61)
AC_INIT([enforcer], [0.0.1], [jad@jadickinson.co.uk])

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_CONFIG_SRCDIR([common/daemon.h])
AC_CONFIG_HEADER([common/config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

ACX_PEDANTIC
ACX_STRICT

AC_PATH_PROG(PERL, perl)
if test -z "$PERL"; then
	AC_MSG_ERROR([perl not found])
fi

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
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([localtime_r memset strdup strerror strstr strtol strtoul])
AC_REPLACE_FUNCS(strlcat)
AC_REPLACE_FUNCS(strlcpy)

AC_SUBST(RUNTIME_PATH)

ACX_LIBXML2
ACX_LIBHSM
ACX_SQLITE3
ACX_DBPARAMS

AH_BOTTOM([
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif           
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif
])


# for now, only SQLite3 is supported
DB_INCLUDES=$SQLITE3_INCLUDES
DB_LIBS=$SQLITE3_LIBS
DB_TYPE=sqlite3
AC_DEFINE_UNQUOTED(SQL_BIN, "$SQLITE3", [database binary])
AC_DEFINE_UNQUOTED(SQL_SETUP, "$prefix/share/opendnssec/database_create.sqlite3", [database setup script])
AC_SUBST(DB_INCLUDES)
AC_SUBST(DB_LIBS)
AC_SUBST(DB_TYPE)

full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_datadir=`eval eval eval eval eval echo "${datadir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`

AC_SUBST([opendnssecdatadir])

opendnssecsysconfdir=$full_sysconfdir/opendnssec
opendnssecdatadir=$full_datadir/opendnssec
opendnsseclocalstatedir="$prefix/var/opendnssec"

keygend_conf_file=$opendnssecsysconfdir/conf.xml
AC_DEFINE_UNQUOTED(CONFIGFILE, ["`eval echo $keygend_conf_file | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC configuration file])

keygend_conf_schema=$opendnssecdatadir/conf.rng
AC_DEFINE_UNQUOTED(CONFIGRNG, ["`eval echo $keygend_conf_schema  | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC configuration schema file])

com_pid_file=$localstatedir/run/opendnssec/communicated.pid
AC_DEFINE_UNQUOTED(COM_PID, ["`eval echo $com_pid_file | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC communicated pid file])

keygen_pid_file=$localstatedir/run/opendnssec/keygend.pid
AC_DEFINE_UNQUOTED(KEYGEN_PID, ["`eval echo $keygen_pid_file | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC keygend pid file])

signer_cli="$prefix/bin/signer_engine_cli update"
AC_DEFINE_UNQUOTED(SIGNER_CLI, ["`eval echo $signer_cli | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC signer engine cli])

AC_DEFINE_UNQUOTED(CONFIGDIR, ["`eval echo $opendnssecsysconfdir | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC configuration files])
AC_DEFINE_UNQUOTED(DATADIR, ["`eval echo $opendnssecdatadir | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC data files])
AC_DEFINE_UNQUOTED(VAR_DIR, ["`eval echo $opendnsseclocalstatedir | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC var directory])


AC_CONFIG_FILES([
Makefile
ksm/Makefile
ksm/include/Makefile
ksm/include/ksm/Makefile
common/Makefile
communicated/Makefile
keygend/Makefile
utils/Makefile
])

AC_OUTPUT
