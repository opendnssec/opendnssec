# routine to help check for compiler flags.
AC_DEFUN([CHECK_COMPILER_FLAG],[
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
