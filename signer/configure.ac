# $Id$

m4_sinclude([version.m4])

AC_PREREQ(2.61)
AC_INIT([opendnssec-signer], OPENDNSSEC_VERSION, [http://trac.opendnssec.org/newticket])

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

OPENDNSSEC_COMMON

AC_CHECK_HEADERS(getopt.h,, [AC_INCLUDES_DEFAULT])

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

# check if setreuid en setregid fail, on MacOSX10.4(darwin8).
if echo $build_os | grep darwin8 > /dev/null; then
    AC_DEFINE(DARWIN_BROKEN_SETREUID, 1, [Define this if on macOSX10.4-darwin8 and setreuid and setregid do not work])
fi

ACX_PEDANTIC
ACX_STRICT
ACX_RT
ACX_BROKEN_SETRES

# Check for some target-specific stuff
case "$host" in
*-*-darwin*)
    AC_DEFINE(SETEUID_BREAKS_SETUID, 1,
        [Define if your platform breaks doing a seteuid before a setuid])
    AC_DEFINE(BROKEN_SETREUID, 1, [Define if your setreuid() is broken])
    AC_DEFINE(BROKEN_SETREGID, 1, [Define if your setregid() is broken])
    ;;
esac

AC_DEFUN([AC_CHECK_STRPTIME],
[AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING(whether strptime needs defines)
AC_CACHE_VAL(ac_cv_c_strptime_needs_defs,
[
cat >conftest.c <<EOF
#include <time.h>
void testing (void) { struct tm t; char *timestr; strptime(timestr, "%Y%m", &t); }
EOF
if test -z "`$CC -Wall -Werror -c conftest.c 2>&1`"; then
eval "ac_cv_c_strptime_needs_defs=no"
else
eval "ac_cv_c_strptime_needs_defs=yes"
fi
rm -f conftest*
])

AC_MSG_RESULT($ac_cv_c_strptime_needs_defs)
if test $ac_cv_c_strptime_needs_defs = yes; then
AC_DEFINE_UNQUOTED([STRPTIME_NEEDS_DEFINES], 1, [strptime is available from time.h with some defines.])
fi
])dnl

AC_CHECK_STRPTIME


ACX_LIBXML2
ACX_LIBHSM
ACX_LDNS(1,6,4)
ACX_PTHREAD

LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"

AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/ods-signerd.c])
AC_CONFIG_HEADERS([src/config.h])
AC_PROG_INSTALL
AC_PROG_LIBTOOL

AC_DEFINE_UNQUOTED(ODS_SE_PIDFILE,  ["$OPENDNSSEC_SIGNER_PIDFILE"],    [Path to the OpenDNSSEC signer engine pid file])
AC_DEFINE_UNQUOTED(ODS_ZF_PIDFILE,  ["$OPENDNSSEC_FETCH_PIDFILE"],    [Path to the OpenDNSSEC signer engine pid file])
AC_DEFINE_UNQUOTED(ODS_SE_SOCKFILE, ["$OPENDNSSEC_SIGNER_SOCKET"],     [Path to the OpenDNSSEC signer engine socket file])
AC_DEFINE_UNQUOTED(ODS_SE_WORKDIR,  ["$OPENDNSSEC_SIGNER_WORKINGDIR"], [Path to the OpenDNSSEC signer engine working directory])
AC_DEFINE_UNQUOTED(ODS_SE_CFGFILE,  ["$OPENDNSSEC_CONFIG_FILE"],       [Path to the OpenDNSSEC config file])
AC_DEFINE_UNQUOTED(ODS_SE_RNGDIR,   ["$OPENDNSSEC_SCHEMA_DIR"],        [Path to the OpenDNSSEC data files])
AC_DEFINE_UNQUOTED(ODS_SE_ENGINE,   ["$OPENDNSSEC_SIGNER_ENGINE -vvv"], [Path to the OpenDNSSEC signer engine binary])
AC_DEFINE_UNQUOTED(ODS_SE_CLI,   ["$OPENDNSSEC_SIGNER_CLI"], [Path to the OpenDNSSEC signer client binary])
AC_DEFINE_UNQUOTED(ODS_SE_AUDITOR,  ["$OPENDNSSEC_SIGNER_AUDITOR"],    [Path to the OpenDNSSEC auditor binary])

AC_CHECK_FUNCS([arc4random arc4random_uniform])
AC_CHECK_FUNCS([chown stat exit time atoi getpid waitpid clock_gettime sigfillset])
AC_CHECK_FUNCS([malloc calloc realloc free])
AC_CHECK_FUNCS([strlen strncmp strncat strncpy strerror strncasecmp strdup])
AC_CHECK_FUNCS([fgetc fopen fclose ferror fprintf vsnprintf fflush])
AC_CHECK_FUNCS([openlog closelog syslog])
AC_CHECK_FUNCS([close unlink fcntl socket listen bzero])
AC_CHECK_FUNCS([va_start va_end])
AC_CHECK_FUNCS([xmlInitParser xmlCleanupParser xmlCleanupThreads])
AC_CHECK_FUNCS([pthread_mutex_init pthread_mutex_destroy pthread_mutex_lock pthread_mutex_unlock])
AC_CHECK_FUNCS([pthread_cond_init pthread_cond_signal pthread_cond_destroy pthread_cond_wait pthread_cond_timedwait])
AC_CHECK_FUNCS([pthread_create pthread_detach pthread_self pthread_join pthread_sigmask])

# Checks for header files.
AC_CHECK_HEADERS([errno.h getopt.h pthread.h signal.h stdarg.h stdint.h stdio.h stdlib.h string.h strings.h syslog.h time.h unistd.h])
AC_CHECK_HEADERS([libxml/parser.h libxml/relaxng.h libxml/xmlreader.h libxml/xpath.h])
AC_CHECK_HEADERS([sys/select.h sys/socket.h sys/stat.h sys/time.h sys/types.h sys/wait.h])

AC_ARG_ENABLE(timeshift,
        AC_HELP_STRING([--enable-timeshift], [Enable timeshift debug]),
                [enable_timeshift="${enableval}"],
                [enable_timeshift="no"])
if test "x${enable_timeshift}" = "xyes"; then
        AC_DEFINE_UNQUOTED(ENFORCER_TIMESHIFT, 1, [timeshift debug])
        AC_MSG_CHECKING(if we should do timeshift debugging)
        AC_MSG_RESULT(yes)
fi

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

#define ODS_SE_MAXLINE 1024
#define ODS_SE_SIGNERTHREADS 1
#define ODS_SE_WORKERTHREADS 8
#define ODS_SE_STOP_RESPONSE "Engine shut down."
#define ODS_SE_MAX_BACKOFF 3600

])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])

AC_OUTPUT
