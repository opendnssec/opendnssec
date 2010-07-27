# $Id$

AC_DEFUN([ACX_RT],[
	RT_LIBS="-lrt"

	tmp_LIBS=$LIBS
	LIBS="$LIBS $RT_LIBS"

	AC_CHECK_LIB(
		[rt],
		[clock_gettime],
		[AC_DEFINE(HAVE_CLOCK_GETTIME, 1, [Define if you have clock_gettime])],
		[RT_LIBS=""]
	)

	LIBS=$tmp_LIBS
	AC_SUBST(RT_LIBS)

	AC_CHECK_HEADERS(sys/time.h time.h)

	if test "x$RT_LIBS" = "x" ; then
		AC_CHECK_FUNC(
			[gettimeofday],
			[],
			[AC_MSG_ERROR(Could not find the function clock_gettime or gettimeofday)]
		)
	fi
])
