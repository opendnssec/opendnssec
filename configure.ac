# $Id$

m4_sinclude([version.m4])

AC_PREREQ(2.61)
AC_INIT([opendnssec], OPENDNSSEC_VERSION, [http://bugs.opendnssec.org/])

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

OPENDNSSEC_COMMON

# extensions
AC_USE_SYSTEM_EXTENSIONS

# standard programs
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# additional programs
AC_PATH_PROG(XMLLINT, xmllint)
AC_PATH_PROG(XSLTPROC, xsltproc)
AC_PATH_PROG(JAVA, java)
AC_PATH_PROG(CP, cp)
AC_DEFINE_UNQUOTED(CP_COMMAND, "$CP", [System cp(3) command])

# building
ACX_ARG_RPATH
ACX_RUNTIME_PATH_ADD
ACX_PEDANTIC
ACX_STRICT

# compiler flags
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

# checks for header files
AC_HEADER_STDC
AC_HEADER_STDBOOL
AC_HEADER_TIME
AC_CHECK_HEADERS([fcntl.h inttypes.h stdio.h stdlib.h string.h syslog.h unistd.h])
AC_CHECK_HEADERS(getopt.h,, [AC_INCLUDES_DEFAULT])
AC_CHECK_HEADERS([errno.h getopt.h pthread.h signal.h stdarg.h stdint.h strings.h])
AC_CHECK_HEADERS([sys/select.h sys/socket.h sys/stat.h sys/time.h sys/types.h sys/wait.h])
AC_CHECK_HEADERS([libxml/parser.h libxml/relaxng.h libxml/xmlreader.h libxml/xpath.h])

# checks for typedefs, structures, and compiler characteristics
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T

# pthread
ACX_PTHREAD
LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"

# checks for library functions
AC_CHECK_FUNCS([arc4random arc4random_uniform])
AC_CHECK_FUNCS([dup2 endpwent select strerror strtol])
AC_CHECK_FUNCS([getpass getpassphrase memset])
AC_CHECK_FUNCS([localtime_r memset strdup strerror strstr strtol strtoul])
AC_CHECK_FUNCS([setregid setreuid])
AC_CHECK_FUNCS([chown stat exit time atoi getpid waitpid sigfillset])
AC_CHECK_FUNCS([malloc calloc realloc free])
AC_CHECK_FUNCS([strlen strncmp strncat strncpy strerror strncasecmp strdup])
AC_CHECK_FUNCS([fgetc fopen fclose ferror fprintf vsnprintf fflush])
AC_CHECK_FUNCS([openlog closelog syslog])
AC_CHECK_FUNCS([openlog_r closelog_r syslog_r vsyslog_r])
AC_CHECK_FUNCS([chroot getgroups setgroups initgroups])
AC_CHECK_FUNCS([close unlink fcntl socket listen bzero])
AC_CHECK_FUNCS([va_start va_end])
AC_CHECK_FUNCS([xmlInitParser xmlCleanupParser xmlCleanupThreads])
AC_CHECK_FUNCS([pthread_mutex_init pthread_mutex_destroy pthread_mutex_lock pthread_mutex_unlock])
AC_CHECK_FUNCS([pthread_cond_init pthread_cond_signal pthread_cond_destroy pthread_cond_wait pthread_cond_timedwait])
AC_CHECK_FUNCS([pthread_create pthread_detach pthread_self pthread_join pthread_sigmask])

AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_VPRINTF

AC_REPLACE_FUNCS(strlcat)
AC_REPLACE_FUNCS(strlcpy)
AC_REPLACE_FUNCS(b64_pton)
AC_REPLACE_FUNCS(b64_ntop)

ACX_BROKEN_SETRES
AC_CHECK_STRPTIME

# find out how to restart named processes
AC_PATH_PROG(PKILL, pkill)
AC_PATH_PROG(KILLALL, killall)
if test -n "$PKILL" -a -x "$PKILL"; then
  AC_DEFINE_UNQUOTED(RESTART_ENFORCERD_CMD, "$PKILL -HUP ods-enforcerd", [Command to restart a named process])
elif test -n "$KILLALL" -a -x "$KILLALL"; then
  AC_DEFINE_UNQUOTED(RESTART_ENFORCERD_CMD, "$KILLALL -HUP ods-enforcerd", [Command to restart a named process])
else
  AC_DEFINE_UNQUOTED(RESTART_ENFORCERD_CMD, "/bin/false", [Command to restart a named process])
fi

# check for some target-specific stuff
case "$host" in
*-*-darwin*)
    AC_DEFINE(SETEUID_BREAKS_SETUID, 1,
	    [Define if your platform breaks doing a seteuid before a setuid])
	AC_DEFINE(BROKEN_SETREUID, 1, [Define if your setreuid() is broken])
	AC_DEFINE(BROKEN_SETREGID, 1, [Define if your setregid() is broken])
    ;;
esac

# timeshift
AC_ARG_ENABLE(timeshift,
	AC_HELP_STRING([--enable-timeshift], [Enable timeshift debug]),
		[enable_timeshift="${enableval}"],
		[enable_timeshift="no"])
AC_MSG_CHECKING(if we should enable timeshift debugging)
if test "x${enable_timeshift}" = "xyes"; then
	AC_MSG_RESULT(yes)
	AC_DEFINE_UNQUOTED(ENFORCER_TIMESHIFT, 1, [timeshift debug])
else
	AC_MSG_RESULT(no)
fi

# common dependencies
ACX_LIBXML2
ACX_LDNS(1,6,12)
ACX_PKCS11_MODULES
ACX_RT
ACX_LIBC
ACX_SSL

# libhsm
ACX_DLOPEN
AC_DEFINE_UNQUOTED([HSM_DEFAULT_CONFIG],["$OPENDNSSEC_CONFIG_FILE"],[Default configuration file.])

# enforcer
AC_PATH_PROG(PERL, perl)
if test -z "$PERL"; then
   AC_MSG_ERROR([perl not found])
fi
ACX_DBPARAMS
ACX_DATABASE_BACKEND
ACX_CUNIT
AC_DEFINE_UNQUOTED(SIGNER_CLI_UPDATE, "$OPENDNSSEC_SIGNER_CLI update", [Path to the OpenDNSSEC signer engine cli])
AM_CONDITIONAL([ENABLE_ENFORCER], [test "${enable_signer}" = "yes"])

# cunit
AM_CONDITIONAL([WITH_CUNIT], [test "${with_cunit}" != "no" -a -n "$CUNIT_LIBS"])

# signer
AC_ARG_ENABLE(signer,
	AC_HELP_STRING([--disable-signer],
		[Disable signer build (default enabled)]),
		[enable_signer="${enableval}"],
		[enable_signer="yes"])
AH_BOTTOM([
	/* define before includes as it specifies what standard to use. */
	#if (defined(HAVE_PSELECT) && !defined (HAVE_PSELECT_PROTO)) \
	        || !defined (HAVE_CTIME_R_PROTO) \
	        || defined (STRPTIME_NEEDS_DEFINES)
	#  ifndef _XOPEN_SOURCE
	#    define _XOPEN_SOURCE 600
	#  endif
	#  ifndef _POSIX_C_SOURCE
	#    define _POSIX_C_SOURCE 200112
	#  endif
	#  ifndef _BSD_SOURCE
	#    define _BSD_SOURCE 1
	#  endif
	#  ifndef __EXTENSIONS__
	#    define __EXTENSIONS__ 1
	#  endif
	#  ifndef _STDC_C99
	#    define _STDC_C99 1
	#  endif
	#  ifndef _ALL_SOURCE
	#    define _ALL_SOURCE 1
	#  endif
	#endif
])
AM_CONDITIONAL([ENABLE_SIGNER], [test "${enable_signer}" = "yes"])

# plugins/eppclient
AC_ARG_ENABLE(eppclient,
	AC_HELP_STRING([--enable-eppclient],
		[Enable eppclient build (default disabled)]),
		[enable_eppclient="${enableval}"],
		[enable_eppclient="no"])
if test "x${enable_eppclient}" = "xyes"; then
	AC_SEARCH_LIBS(nanosleep, rt posix4, AC_DEFINE(HAVE_NANOSLEEP, 1,
		[Define if you have nanosleep]))

	# ACX_LIBXML2
	# ACX_LDNS(1,6,6)
	ACX_LIBSQLITE3
	LIBCURL_CHECK_CONFIG([yes], [7.18.2], [], [AC_MSG_ERROR(["libcurl not found"])])

	EPPCLIENTD_CONF=$OPENDNSSEC_SYSCONF_DIR/eppclientd.conf
	EPPCLIENTD_DB=$OPENDNSSEC_LOCALSTATE_DIR/eppclientd.sqlite
	EPPCLIENTD_PID=$OPENDNSSEC_PID_DIR/eppclientd.pid
	EPPCLIENTD_PIPE=$OPENDNSSEC_PID_DIR/eppclientd.pipe

	AC_SUBST([EPPCLIENTD_CONF])
	AC_SUBST([EPPCLIENTD_DB])
	AC_SUBST([EPPCLIENTD_PID])
	AC_SUBST([EPPCLIENTD_PIPE])

	AC_DEFINE_UNQUOTED(EPPCLIENTD_CONF, "$EPPCLIENTD_CONF", [Path to the eppclientd.conf])
fi
AM_CONDITIONAL([ENABLE_EPPCLIENT], [test "${enable_eppclient}" = "yes"])

# check for a green cucumber (but only if we can shift time)
if test "x${enable_timeshift}" = "xyes"; then
	AC_PATH_PROG(CUCUMBER, cucumber)
fi
AM_CONDITIONAL([WITH_CUCUMBER], [test -x "${CUCUMBER}"])

# doxygen
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN(${PACKAGE_NAME}, [Doxyfile], [doxygen-doc])


AC_CONFIG_HEADER([common/config.h])

AC_CONFIG_FILES([
	Makefile
	Doxyfile
	common/Makefile
	conf/Makefile
	conf/addns.xml
	conf/conf.xml
	conf/enforcerstate.xml
	conf/kasp.xml
	conf/signconf.xml
	conf/zonelist.xml
	enforcer/Makefile
	enforcer/common/Makefile
	enforcer/enforcerd/Makefile
	enforcer/enforcerd/ods-enforcerd.8
	enforcer/ksm/Makefile
	enforcer/ksm/include/Makefile
	enforcer/ksm/include/ksm/Makefile
	enforcer/test/Makefile
	enforcer/test/cucumber/Makefile
	enforcer/test/cucumber/c_conf.xml
	enforcer/test/cucumber/c_kasp.xml
	enforcer/test/cucumber/c_zonelist.base.xml
	enforcer/test/cunit/Makefile
	enforcer/test/cunit/database_setup_mysql.sh
	enforcer/test/cunit/database_setup_sqlite3.sh
	enforcer/utils/Makefile
	enforcer/utils/ods-kaspcheck.1
	enforcer/utils/ods-ksmutil.1
	libhsm/Makefile
	libhsm/src/Makefile
	libhsm/src/bin/Makefile
	libhsm/src/bin/ods-hsmspeed.1
	libhsm/src/bin/ods-hsmutil.1
	libhsm/src/lib/Makefile
	libhsm/checks/Makefile
	libhsm/checks/conf-softhsm.xml
	libhsm/checks/conf-sca6000.xml
	libhsm/checks/conf-etoken.xml
	libhsm/checks/conf-multi.xml
	libhsm/checks/conf-opensc.xml
	libhsm/checks/conf-ncipher.xml
	libhsm/checks/conf-aepkeyper.xml
	plugins/eppclient/Makefile
	plugins/eppclient/src/Makefile
	plugins/eppclient/src/eppclient.8
	plugins/eppclient/src/eppclientd.8
	plugins/eppclient/src/eppclientd.conf
	plugins/eppclient/src/eppclientd.conf.5
	signer/Makefile
	signer/man/Makefile
	signer/man/ods-signer.8
	signer/man/ods-signerd.8
	signer/src/Makefile
	tools/Makefile
	tools/ods-control
	tools/solaris/Makefile
	tools/solaris/ods-enforcerd.init
	tools/solaris/ods-signerd.init
	tools/ods-timing.5
	tools/opendnssec.7
	tools/ods-control.8
	tools/ods-kasp2html
])

AC_OUTPUT
