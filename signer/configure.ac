# $Id$

m4_sinclude([../version.m4])

AC_PREREQ(2.61)
AC_INIT([opendnssec-signer], OPENDNSSEC_VERSION)

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

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

fetch_pid_file=$localstatedir/run/opendnssec/zone_fetcher.pid
signer_cli="$prefix/bin/ods-signer sign"

AC_DEFINE_UNQUOTED(FETCH_PIDFILE, ["`eval echo $fetch_pid_file | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC zone fetcher pid file])
AC_DEFINE_UNQUOTED(SIGNER_CLI_COMMAND, ["`eval echo $signer_cli | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC signer engine cli])

# check if setreuid en setregid fail, on MacOSX10.4(darwin8).
if echo $build_os | grep darwin8 > /dev/null; then
    AC_DEFINE(DARWIN_BROKEN_SETREUID, 1, [Define this if on macOSX10.4-darwin8 and setreuid and setregid do not work])
fi

AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(nsl, inet_pton)

ACX_PEDANTIC
ACX_STRICT

ACX_LDNS
ACX_LIBXML2
ACX_LIBHSM

full_libexecdir=`eval eval eval eval eval echo "${libexecdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
opendnsseclibexecdir=$full_libexecdir/opendnssec

AC_SUBST([opendnsseclibexecdir])

AM_INIT_AUTOMAKE
AM_PATH_PYTHON
AC_CONFIG_HEADERS([tools/config.h])
AC_PROG_INSTALL
AC_PROG_LIBTOOL

AC_CONFIG_FILES([
	Makefile
	tools/Makefile
	signer_engine/Makefile
	signer_engine/EngineConfig.py
	signer_engine/ods-signer
	signer_engine/ods-signerd
])

AC_OUTPUT
