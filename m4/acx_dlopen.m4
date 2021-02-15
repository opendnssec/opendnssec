AC_DEFUN([ACX_DLOPEN],[
	tmp_SUCCESS="no"

	# Unix
	AC_CHECK_FUNC(
		[dlopen],
		[
			AC_DEFINE(HAVE_DLOPEN, 1, [Define if you have dlopen])
			tmp_SUCCESS="yes"
		],
		[
			AC_CHECK_LIB(
				[dl],
				[dlopen],
				[
					AC_DEFINE(HAVE_DLOPEN, 1, [Define if you have dlopen])
					LIBS="$LIBS -ldl"
					tmp_SUCCESS="yes"
				]
			)
		]
	)

	# Windows
	if test "$tmp_SUCCESS" = "no"
	then
		AC_MSG_CHECKING([for LoadLibrary])
		AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <windows.h>]],[[LoadLibrary(NULL);]])], [AC_DEFINE([HAVE_LOADLIBRARY], [1], [Define if you have LoadLibrary])], [])
	fi
])
