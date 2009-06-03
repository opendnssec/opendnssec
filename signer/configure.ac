
AC_INIT(signer_engine, 0.1, jelte@NLnetLabs.nl)

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

# check for hsm development source tree
AC_MSG_CHECKING([for hsm devel source])
hsm_dev_dir=../libhsm/src
if test -f $hsm_dev_dir/libhsm.h ; then
	AC_MSG_RESULT([using $hsm_dev_dir])
	CFLAGS="$CFLAGS -I../$hsm_dev_dir"
	LDFLAGS="-L../$hsm_dev_dir/.libs $LDFLAGS"
	LIBS="$LIBS -lhsm"
	AC_DEFINE(HAVE_LIBhsm, 1, [If the hsm library is available.])
	hsmDIR="$hsm_dev_dir"
else
	AC_MSG_RESULT([no])
	AC_CHECK_LIB(hsm, hsm_open,, [
			AC_MSG_ERROR([Can't find hsm library])
		]
	)
fi

opendnsseclibexecdir="\$(libexecdir)/opendnssec"

AC_SUBST([opendnsseclibexecdir])

AM_INIT_AUTOMAKE
AM_PATH_PYTHON
AC_CONFIG_HEADERS([tools/config.h])
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_OUTPUT(Makefile conf.xml.sample tools/Makefile signer_engine/Makefile signer_engine/signer_engine)
