# $Id$

AC_DEFUN([AC_CHECK_STRPTIME],[
	AC_REQUIRE([AC_PROG_CC])

	AC_MSG_CHECKING(whether strptime needs defines)

	AC_CACHE_VAL(ac_cv_c_strptime_needs_defs,[
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
])
