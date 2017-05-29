m4_sinclude([version.m4])

AC_PREREQ(2.61)
AC_INIT([opendnssec], OPENDNSSEC_VERSION, [http://bugs.opendnssec.org/])
AM_DEFAULT_VERBOSITY="0"
AC_SUBST([AM_DEFAULT_VERBOSITY])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_MACRO_DIR([m4])
ACX_PREFIXHACK

OPENDNSSEC_COMMON

# extensions
AC_USE_SYSTEM_EXTENSIONS

# standard programs
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET
AC_PROG_CXX

# additional programs
AC_PATH_PROG(XMLLINT, xmllint)
AC_PATH_PROG(XSLTPROC, xsltproc)
AC_PATH_PROG(JAVA, java)
AC_PATH_PROG(CP, cp)
AC_DEFINE_UNQUOTED(CP_COMMAND, "$CP", [System cp(3) command])

# building, compiler flags
AC_PROG_CC_STDC
#AC_PROG_CC_C99
ACX_PEDANTIC
AX_COMPILER_FLAGS_CFLAGS
AX_C___ATTRIBUTE__
ACX_ARG_RPATH
ACX_RUNTIME_PATH_ADD
AX_CFLAGS_WARN_ALL

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
AC_MSG_CHECKING(for union semun)
AC_TRY_COMPILE([#include <sys/types.h>
                #include <sys/ipc.h>
                #include <sys/sem.h>],
               [union semun arg;],
               [have_union_semun=1],
               [have_union_semun=0]
)
if test $have_union_semun = 1; then
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_UNION_SEMUN, 1, [union semun is defined])
else
  AC_MSG_RESULT(no)
fi

# pthread
ACX_PTHREAD(
  [AC_DEFINE([HAVE_PTHREAD], [1],
    [Define if you have POSIX threads libraries and header files.])
    LDFLAGS="$CFLAGS $PTHREAD_CFLAGS $LDFLAGS $PTHREAD_LIBS $LIBS"])

LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS $WARN_CFLAGS"
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
AC_CHECK_FUNCS([fgetc fopen fclose ferror fprintf vsnprintf snprintf fflush])
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

# check for some target-specific stuff
case "$host" in
*-*-darwin*)
    AC_DEFINE(SETEUID_BREAKS_SETUID, 1,
	    [Define if your platform breaks doing a seteuid before a setuid])
    AC_DEFINE(BROKEN_SETREUID, 1, [Define if your setreuid() is broken])
    AC_DEFINE(BROKEN_SETREGID, 1, [Define if your setregid() is broken])
    ;;
*-*-netbsd*)
    AC_DEFINE(_NETBSD_SOURCE, 1, [Enable functions on BSD])
    ;;
esac

# check for the sockaddr_un.sun_len member
AC_CHECK_MEMBER([struct sockaddr_un.sun_len],
    [AC_DEFINE(HAVE_SOCKADDR_SUN_LEN,1,[Have the sockaddr_un.sun_len member.])],
    [],
    [ #include <sys/types.h>
      #include <sys/un.h>
    ])

# common dependencies
ACX_LIBXML2
ACX_LDNS(1,6,17)
ACX_LDNS_NOT(1,6,14, [binary incompatibility, see http://open.nlnetlabs.nl/pipermail/ldns-users/2012-October/000564.html])
ACX_LDNS_NOT(1,6,15, [fail to create NSEC3 bitmap for empty non-terminals, see http://www.nlnetlabs.nl/pipermail/ldns-users/2012-November/000565.html])
ACX_PKCS11_MODULES
ACX_RT
ACX_LIBC
ACX_SSL
ACX_CUNIT

# cunit
AM_CONDITIONAL([WITH_CUNIT], [test "${with_cunit}" != "no" -a -n "$CUNIT_LIBS"])

# libhsm
ACX_DLOPEN
AC_DEFINE_UNQUOTED([HSM_DEFAULT_CONFIG],["$OPENDNSSEC_CONFIG_FILE"],[Default configuration file.])

# enforcer
AC_ARG_ENABLE(enforcer,
	AC_HELP_STRING([--disable-enforcer],
		[Disable enforcer build (default enabled)]),
		[enable_enforcer="${enableval}"],
		[enable_enforcer="yes"])
if test "x${enable_enforcer}" = "xyes"; then
	AC_DEFINE_UNQUOTED(SIGNER_CLI_UPDATE, "$OPENDNSSEC_SIGNER_CLI update", [Path to the OpenDNSSEC signer engine cli])
	ACX_ENFORCER_DATABASE
	ACX_LIBREADLINE
fi
AM_CONDITIONAL([ENABLE_ENFORCER], [test "${enable_enforcer}" = "yes"])

# signer
AC_ARG_ENABLE(signer,
	AC_HELP_STRING([--disable-signer],
		[Disable signer build (default enabled)]),
		[enable_signer="${enableval}"],
		[enable_signer="yes"])
AM_CONDITIONAL([ENABLE_SIGNER], [test "${enable_signer}" = "yes"])

INSTALLATIONCOND=""
AC_ARG_ENABLE(installation-user,
	AC_HELP_STRING([--enable-installation-user],
		[Install for usage by specific user (default=disabled)]),
		[enable_installationuser=$enableval],
		[enable_installationuser="no"])
AC_ARG_ENABLE(installation-group,
	AC_HELP_STRING([--enable-installation-group],
		[Install for usage by specific group (default=disabled)]),
		[enable_installationgroup=$enableval],
		[enable_installationgroup="no"])
if test "x${enable_installationuser}" != "xno"; then
	INSTALLATIONUSER="${enable_installationuser}"
	INSTALLATIONUSERARG="-o${enable_installationuser}"
	INSTALLATIONCOND="user"
else
	INSTALLATIONUSER=""
	INSTALLATIONUSERARG=""
fi
if test "x${enable_installationgroup}" != "xno"; then
	INSTALLATIONGROUP="${enable_installationgroup}"
	INSTALLATIONGROUPARG="-g${enable_installationgroup}"
	if test "x${enable_installationuser}" != "xno"; then
		INSTALLATIONCOND="both"
	else
		INSTALLATIONCOND="group"
	fi
else
	INSTALLATIONGROUP=""
	INSTALLATIONGROUPARG=""
fi
AC_SUBST([INSTALLATIONGROUP])
AC_SUBST([INSTALLATIONGROUPARG])
AC_SUBST([INSTALLATIONUSER])
AC_SUBST([INSTALLATIONUSERARG])
AC_SUBST([INSTALLATIONCOND])

# doxygen
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN(${PACKAGE_NAME}, [Doxyfile], [doxygen-doc])

AC_CHECK_FUNC(backtrace, [AC_DEFINE([HAVE_BACKTRACE], [1], [Define if backtrace supported])])
AC_CHECK_LIB(backtrace, backtrace_full, [AC_DEFINE([HAVE_BACKTRACE_FULL], [1], [Define if backtrace_full supported]) LIBS="$LIBS -lbacktrace"])
AC_CHECK_LIB(unwind, unw_backtrace, [AC_CHECK_HEADERS(libunwind.h, [AC_DEFINE([HAVE_LIBUNWIND], [1], [Define if libunwind supported]) LIBS="$LIBS -lunwind -lunwind-x86_64"], [], [])])

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
	enforcer/src/Makefile
	enforcer/man/Makefile
	enforcer/src/db/test/Makefile
	enforcer/man/ods-enforcer.8
	enforcer/man/ods-enforcer-db-setup.8
	enforcer/man/ods-enforcerd.8
	enforcer/src/utils/Makefile
	enforcer/src/utils/ods-kaspcheck.1
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
	signer/Makefile
	signer/man/Makefile
	signer/man/ods-signer.8
	signer/man/ods-signerd.8
	signer/src/Makefile
	signer/src/test/Makefile
	tools/Makefile
	tools/ods-control
	tools/solaris/Makefile
	tools/solaris/ods-enforcerd.init
	tools/solaris/ods-signerd.init
	tools/ods-timing.5
	tools/ods-kasp.5
	tools/opendnssec.7
	tools/ods-control.8
	tools/ods-kasp2html
])

AC_OUTPUT
