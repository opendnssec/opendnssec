# $Id$

m4_sinclude([../version.m4])

AC_PREREQ(2.61)
AC_INIT([opendnssec-enforcer], OPENDNSSEC_VERSION)

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

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

CHECK_COMPILER_FLAG(std=c99, [C99FLAG="-std=c99"])
CHECK_COMPILER_FLAG(xc99, [C99FLAG="-xc99"])
CHECK_COMPILER_FLAG_NEEDED($C99FLAG, [#include <stdbool.h>], [CFLAGS="$CFLAGS $C99FLAG"])

CHECK_COMPILER_FLAG_NEEDED(-D__EXTENSIONS__,
[
#include "confdefs.h"
#include <stdlib.h>
#include <unistd.h>

int test() {
	int a;
	char **opts = NULL;
	a = getopt(2, opts, "a");
	return a;
}
], [CFLAGS="-D__EXTENSIONS__ $CFLAGS"])

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
AC_CHECK_FUNCS([localtime_r memset strdup strerror strstr strtol strtoul setregid setreuid])

AC_CHECK_FUNCS(setresuid, [
	dnl Some platorms have setresuid that isn't implemented, test for this
	AC_MSG_CHECKING(if setresuid seems to work)
	AC_RUN_IFELSE(
		[AC_LANG_SOURCE([[
#include <stdlib.h>
#include <errno.h>
int main(){errno=0; setresuid(0,0,0); if (errno==ENOSYS) exit(1); else exit(0);}
		]])],
		[AC_MSG_RESULT(yes)],
		[AC_DEFINE(BROKEN_SETRESUID, 1,
			[Define if your setresuid() is broken])
		 AC_MSG_RESULT(not implemented)],
		[AC_MSG_WARN([cross compiling: not checking setresuid])]
	)
])

AC_CHECK_FUNCS(setresgid, [
	dnl Some platorms have setresgid that isn't implemented, test for this
	AC_MSG_CHECKING(if setresgid seems to work)
	AC_RUN_IFELSE(
		[AC_LANG_SOURCE([[
#include <stdlib.h>
#include <errno.h>
int main(){errno=0; setresgid(0,0,0); if (errno==ENOSYS) exit(1); else exit(0);}
		]])],
		[AC_MSG_RESULT(yes)],
		[AC_DEFINE(BROKEN_SETRESGID, 1,
			[Define if your setresgid() is broken])
		 AC_MSG_RESULT(not implemented)],
		[AC_MSG_WARN([cross compiling: not checking setresuid])]
	)
])

AC_REPLACE_FUNCS(strlcat)
AC_REPLACE_FUNCS(strlcpy)

AC_SUBST(RUNTIME_PATH)

ACX_CUNIT
ACX_LIBXML2
ACX_LIBHSM
ACX_DBPARAMS
ACX_LDNS

AH_BOTTOM([
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif           
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif
])

# Check for mysql 
AC_ARG_WITH(mysql, 
            [  --with-mysql=DIR        Look for mysql in this dir ], 
            [ MYSQL_PATH="$withval"], 
            [ with_mysql=no ] 
            )
if test "x$with_mysql" = "xno"; then
    # for now, only SQLite3 is supported
    ACX_SQLITE3

    DB_INCLUDES=$SQLITE3_INCLUDES
    DB_LIBS=$SQLITE3_LIBS
    DB_TYPE=sqlite3
    AC_DEFINE_UNQUOTED(SQL_BIN, "$SQLITE3", [database binary])
    AC_DEFINE_UNQUOTED(SQL_SETUP, "$prefix/share/opendnssec/database_create.sqlite3", [database setup script])
    AC_SUBST(DB_INCLUDES)
    AC_SUBST(DB_LIBS)
    AC_SUBST(DB_TYPE)
else 
    DB_TYPE="MYSQL" 
    if test "x$MYSQL_PATH" = "x"; then 
        AC_PATH_PROGS(MYSQL_CONFIG, mysql_config, mysql_config, $PATH) 
        AC_PATH_PROG(MYSQL, mysql) 
        AC_DEFINE_UNQUOTED(SQL_BIN, "mysql", [database binary]) 
    else 
        AC_PATH_PROGS(MYSQL_CONFIG, mysql_config, mysql_config, $MYSQL_PATH/bin) 
        AC_PATH_PROG(MYSQL, mysql, ,$MYSQL_PATH/bin) 
        AC_DEFINE_UNQUOTED(SQL_BIN, "$MYSQL_PATH/bin/mysql", [database binary]) 
    fi 
    AC_DEFINE_UNQUOTED(SQL_SETUP, "$prefix/share/opendnssec/database_create.mysql", [database setup script]) 
    if test -z "$MYSQL"; then 
        AC_MSG_ERROR([mysql not found]) 
    fi 
    if test -x "$MYSQL_CONFIG" 
    then 
        AC_MSG_CHECKING(mysql version) 
        MYSQL_VERSION="`$MYSQL_CONFIG --version`" 
        AC_MSG_RESULT($MYSQL_VERSION) 
        if test ${MYSQL_VERSION//.*/} -le 4 ; then 
            AC_MSG_ERROR([mysql must be newer than 5.0.0]) 
        fi
        AC_MSG_CHECKING(what are the mysql includes) 
        # MySQL v4 uses --include while v3 uses --cflags 
        DB_INCLUDES="`$MYSQL_CONFIG --include` -DBIG_JOINS=1 -DUSE_MYSQL" || \ 
        DB_INCLUDES="`$MYSQL_CONFIG --cflags`" 
        AC_MSG_RESULT($DB_INCLUDES) 
        AC_MSG_CHECKING(what are the mysql libs) 
        DB_LIBS="`$MYSQL_CONFIG --libs_r`" 
        AC_MSG_RESULT($DB_LIBS) 
    fi 
fi

AM_CONDITIONAL([MYSQL], [test "x$with_mysql" != "xno"])

full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_datadir=`eval eval eval eval eval echo "${datadir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_localstatedir=`eval eval eval eval eval echo "${localstatedir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`

AC_SUBST([opendnssecdatadir])

opendnssecsysconfdir=$full_sysconfdir/opendnssec
opendnssecdatadir=$full_datadir/opendnssec
opendnsseclocalstatedir="$full_localstatedir/opendnssec"

conf_file=$opendnssecsysconfdir/conf.xml
enforcer_pid_file=$localstatedir/run/opendnssec/enforcerd.pid
signer_cli="$prefix/bin/ods-signer update"

AC_DEFINE_UNQUOTED(CONFIG_DIR, ["`eval echo $opendnssecsysconfdir | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC configuration files])
AC_DEFINE_UNQUOTED(CONFIG_FILE, ["`eval echo $conf_file | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC configuration file])

AC_DEFINE_UNQUOTED(ENFORCER_PIDFILE, ["`eval echo $enforcer_pid_file | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC enforcerd pid file])

AC_DEFINE_UNQUOTED(SIGNER_CLI_COMMAND, ["`eval echo $signer_cli | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC signer engine cli])
AC_DEFINE_UNQUOTED(LOCALSTATE_DIR, ["`eval echo $opendnsseclocalstatedir | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC var directory])
AC_DEFINE_UNQUOTED(SCHEMA_DIR, ["`eval echo $opendnssecdatadir | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC data files])

AC_ARG_ENABLE(timeshift,
	AC_HELP_STRING([--enable-timeshift],[Enable timeshift debug]),
	[AC_DEFINE_UNQUOTED(ENFORCER_TIMESHIFT, 1, [timeshift debug])],[])

AC_CONFIG_FILES([
	Makefile
	ksm/Makefile
	ksm/include/Makefile
	ksm/include/ksm/Makefile
	common/Makefile
	enforcerd/Makefile
	utils/Makefile
	test/Makefile
])

# Check for some target-specific stuff
case "$host" in
*-*-darwin*)
    AC_DEFINE(SETEUID_BREAKS_SETUID, 1,
	    [Define if your platform breaks doing a seteuid before a setuid])
	AC_DEFINE(BROKEN_SETREUID, 1, [Define if your setreuid() is broken])
	AC_DEFINE(BROKEN_SETREGID, 1, [Define if your setregid() is broken])
    ;;
esac

AC_OUTPUT
