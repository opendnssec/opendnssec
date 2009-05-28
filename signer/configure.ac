
AC_INIT(signer_engine, 0.1, jelte@NLnetLabs.nl)

#
# some helper functions (taken from ldns)
#
dnl routine to help check for compiler flags.
AC_DEFUN([CHECK_COMPILER_FLAG],
[
	AC_REQUIRE([AC_PROG_CC])
	AC_MSG_CHECKING(whether $CC supports -$1)
	cache=`echo $1 | sed 'y% .=/+-%____p_%'`
	AC_CACHE_VAL(cv_prog_cc_flag_$cache,
	[
		echo 'void f(){}' >conftest.c
		if test -z "`$CC -$1 -c conftest.c 2>&1`"; then
			eval "cv_prog_cc_flag_$cache=yes"
		else
			eval "cv_prog_cc_flag_$cache=no"
		fi
		rm -f conftest*
	])
	if eval "test \"`echo '$cv_prog_cc_flag_'$cache`\" = yes"; then
		AC_MSG_RESULT(yes)
		:
		$2
	else
		AC_MSG_RESULT(no)
		:
		$3
	fi
])

# if the given code compiles without the flag, execute argument 4
# if the given code only compiles with the flag, execute argument 3
# otherwise fail
AC_DEFUN([CHECK_COMPILER_FLAG_NEEDED],
[
	AC_REQUIRE([AC_PROG_CC])
	AC_MSG_CHECKING(whether we need $1 as a flag for $CC)
	cache=`echo $1 | sed 'y% .=/+-%____p_%'`
	AC_CACHE_VAL(cv_prog_cc_flag_needed_$cache,
	[
		echo '$2' > conftest.c
		echo 'void f(){}' >>conftest.c
		if test -z "`$CC $CFLAGS -Werror -Wall -c conftest.c 2>&1`"; then
			eval "cv_prog_cc_flag_needed_$cache=no"
		else
		[
			if test -z "`$CC $CFLAGS $1 -Werror -Wall -c conftest.c 2>&1`"; then
				eval "cv_prog_cc_flag_needed_$cache=yes"
			else
				echo 'Test with flag fails too'
			fi
		]
		fi
		rm -f conftest*
	])
	if eval "test \"`echo '$cv_prog_cc_flag_needed_'$cache`\" = yes"; then
		AC_MSG_RESULT(yes)
		:
		$3
	else
		AC_MSG_RESULT(no)
		:
		$4
	fi
])

#
# Checks start here
#
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

# if caller uses --with-pkcs11, compile support for it in statically
# (it will still be loaded dynamically when ldns_pkcs11_load_functions is called
# with a library name. if that name is NULL, the linked module will be used)
PKCS11_MODULE=""
AC_ARG_WITH(pkcs11-module, 
	AC_HELP_STRING([--with-pkcs11-module=PATH        specify PKCS11 module to build in as default])
	,
	[
		PKCS11_MODULE="$withval"
		AC_DEFINE([HAVE_PKCS11_MODULE], [], [Define if we have a static default PKCS11 module])
	]
)
AC_SUBST(PKCS11_MODULE)

# check for ldns in --with-ldns
AC_ARG_WITH(ldns, 
	AC_HELP_STRING([--with-ldns=PATH        specify prefix of path of ldns library to use])
	,
	[
		specialldnsdir="$withval"
		CFLAGS="$CFLAGS -I$withval/include"
		LDFLAGS="-L$withval/lib $LDFLAGS"
		LDNSDIR="$withval"
	]
)

# check for ldns on system
AC_CHECK_LIB(ldns, ldns_rr_new,, [
		AC_MSG_ERROR([Can't find ldns library])
	]
)

# check whether our linked ldns is actually recent enough
AC_CHECK_FUNC(ldns_sha1, [], [
		AC_MSG_ERROR([ldns library too old, please update it])
	]
)

# check for hsm
AC_ARG_WITH(hsm, 
	AC_HELP_STRING([--with-hsm=PATH        specify prefix of path of hsm library to use])
	,
	[
		specialhsmdir="$withval"
		CFLAGS="$CFLAGS -I$withval/include"
		LDFLAGS="-L$withval -L$withval/lib $LDFLAGS"
		hsmDIR="$withval"
	]
)

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
AC_OUTPUT(Makefile conf.xml.sample tools/Makefile signer_engine/Makefile signer_engine/signer_engine)
