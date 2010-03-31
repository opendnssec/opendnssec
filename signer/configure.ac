# $Id$

m4_sinclude([version.m4])

AC_PREREQ(2.61)
AC_INIT([opendnssec-signer], OPENDNSSEC_VERSION)

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

AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(nsl, inet_pton)

ACX_PEDANTIC
ACX_STRICT

ACX_LDNS(1,6,4)
ACX_LIBXML2
ACX_LIBHSM

AM_PATH_PYTHON
ACX_PYTHON_MODULE([getopt os sys socket time traceback threading syslog signal errno grp pwd re Ft.Xml.XPath xml.dom xml.parsers.expat subprocess optparse datetime getpass shutil commands])

AC_DEFINE_UNQUOTED(SIGNER_PIDFILE, ["$OPENDNSSEC_SIGNER_PIDFILE"], [Path to the OpenDNSSEC signer engine pid file])
AC_DEFINE_UNQUOTED(FETCH_PIDFILE, ["$OPENDNSSEC_ENFORCER_PIDFILE"], [Path to the OpenDNSSEC zone fetcher pid file])
AC_DEFINE_UNQUOTED(SIGNER_CLI_SIGN, ["$OPENDNSSEC_SIGNER_CLI sign"], [Path to the OpenDNSSEC signer engine cli])

AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([tools/config.h])
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Checks for library functions.
AC_CHECK_FUNCS([arc4random arc4random_uniform])

ACX_BROKEN_SETRES

AC_CONFIG_FILES([
	Makefile
	tools/Makefile
	signer_engine/Makefile
	signer_engine/Engine.py
	signer_engine/EngineConfig.py
	signer_engine/ods-signer
	signer_engine/ods-signer.8
	signer_engine/ods-signerd
	signer_engine/ods-signerd.8	
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
