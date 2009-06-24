# $Id$

AC_INIT([signer_engine], [0.1], [jelte@NLnetLabs.nl])

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

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

AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(nsl, inet_pton)

ACX_PEDANTIC
ACX_STRICT

ACX_LDNS
ACX_LIBXML2
ACX_LIBHSM

opendnsseclibexecdir="\$(libexecdir)/opendnssec"

AC_SUBST([opendnsseclibexecdir])

AM_INIT_AUTOMAKE
AM_PATH_PYTHON
AC_CONFIG_HEADERS([tools/config.h])
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_OUTPUT(Makefile conf.xml.sample tools/Makefile signer_engine/Makefile signer_engine/signer_engine)
