# $Id$

AC_PREREQ(2.61)
AC_INIT([libksm], [0.0.1], [jad@jadickinson.co.uk])

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

AC_CONFIG_SRCDIR([src/ksm_key.c])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PATH_PROG(PERL, perl)
if test -z "$PERL"; then
   AC_MSG_ERROR([perl not found])
fi

ACX_PEDANTIC
ACX_STRICT

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([limits.h stdint.h stdlib.h string.h strings.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([localtime_r memset strdup strerror strstr strtol strtoul])
AC_REPLACE_FUNCS(strlcat)
AC_REPLACE_FUNCS(strlcpy)

ACX_LIBXML2
ACX_CUNIT
ACX_LIBHSM
ACX_SQLITE3
ACX_DBPARAMS

# for now, only SQLite3 is supported
DB_INCLUDES=$SQLITE3_INCLUDES
DB_LIBS=$SQLITE3_LIBS
DB_TYPE=sqlite3
AC_DEFINE_UNQUOTED(SQL_BIN, "$SQLITE3", [database binary])
AC_DEFINE_UNQUOTED(SQL_SETUP, "$prefix/share/opendnssec/database_create.sqlite3", [database setup script])

AC_SUBST(DB_INCLUDES)
AC_SUBST(DB_LIBS)
AC_SUBST(DB_TYPE)

AH_BOTTOM([
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif           
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif
])

opendnssecsysconf="\$(sysconfdir)/opendnssec"
ksmdatadir="\$(datadir)/opendnssec"
ksmincludedir="\$(includedir)/ksm"

AC_SUBST([opendnssecsysconf])
AC_SUBST([ksmdatadir])
AC_SUBST([ksmincludedir])

# Set up the default configuration file location
conf_file_dir=$sysconfdir/opendnssec
AC_DEFINE_UNQUOTED(CONFIGDIR, ["`eval echo $conf_file_dir | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC configuration files])

open_var_dir="$prefix/var/opendnssec"
AC_DEFINE_UNQUOTED(VAR_DIR, ["`eval echo $open_var_dir | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC var directory])

signer_cli="$prefix/bin/signer_engine_cli update"
AC_DEFINE_UNQUOTED(SIGNER_CLI, ["`eval echo $signer_cli | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC signer engine cli])

AC_CONFIG_FILES([
Makefile
src/Makefile
src/include/Makefile
src/include/ksm/Makefile
utils/Makefile
test/Makefile
])

AC_CONFIG_HEADER([src/include/ksm/config.h])
AC_OUTPUT
