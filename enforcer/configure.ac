# $Id$

m4_sinclude([version.m4])

AC_PREREQ(2.61)
AC_INIT([opendnssec-enforcer], OPENDNSSEC_VERSION)

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

OPENDNSSEC_COMMON

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
AC_CHECK_FUNCS([arc4random arc4random_uniform])

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
ACX_LDNS(1,6,4)
ACX_DATABASE_BACKEND

AH_BOTTOM([
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif           
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif
])

AC_DEFINE_UNQUOTED(CONFIG_DIR, "$OPENDNSSEC_CONFIG_DIR", [Path to the OpenDNSSEC configuration files])
AC_DEFINE_UNQUOTED(CONFIG_FILE, "$OPENDNSSEC_CONFIG_FILE", [Path to the OpenDNSSEC configuration file])
AC_DEFINE_UNQUOTED(LOCALSTATE_DIR, "$OPENDNSSEC_STATE_DIR", [Path to the OpenDNSSEC var directory])
AC_DEFINE_UNQUOTED(SCHEMA_DIR, "$OPENDNSSEC_SCHEMA_DIR", [Path to the OpenDNSSEC data files])
AC_DEFINE_UNQUOTED(ENFORCER_PIDFILE, "$OPENDNSSEC_ENFORCER_PIDFILE", [Path to the OpenDNSSEC enforcerd pid file])
AC_DEFINE_UNQUOTED(SIGNER_CLI_UPDATE, "$OPENDNSSEC_SIGNER_CLI update", [Path to the OpenDNSSEC signer engine cli])

AC_ARG_ENABLE(timeshift,
	AC_HELP_STRING([--enable-timeshift], [Enable timeshift debug]),
		[enable_timeshift="${enableval}"],
		[enable_timeshift="no"])
if test "x${enable_timeshift}" = "xyes"; then
	AC_DEFINE_UNQUOTED(ENFORCER_TIMESHIFT, 1, [timeshift debug])
	AC_MSG_CHECKING(if we should do timeshift debugging)
	AC_MSG_RESULT(yes)
fi

AC_CONFIG_FILES([
	Makefile
	ksm/Makefile
	ksm/include/Makefile
	ksm/include/ksm/Makefile
	common/Makefile
	enforcerd/Makefile
	enforcerd/ods-enforcerd.8
	utils/Makefile
	utils/ods-ksmutil.1
	test/Makefile
])

# Find out how to restart named processes
AC_PATH_PROG(PKILL, pkill)
AC_PATH_PROG(KILLALL, killall)
if test -n "$PKILL" -a -x "$PKILL"; then
  AC_DEFINE_UNQUOTED(RESTART_ENFORCERD_CMD, "$PKILL -HUP ods-enforcerd", [Command to restart a named process])
elif test -n "$KILLALL" -a -x "$KILLALL"; then
  AC_DEFINE_UNQUOTED(RESTART_ENFORCERD_CMD, "$KILLALL -HUP ods-enforcerd", [Command to restart a named process])
else
  AC_DEFINE_UNQUOTED(RESTART_ENFORCERD_CMD, "/bin/false", [Command to restart a named process])
fi

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
