# $Id$

AC_DEFUN([ACX_DLOPEN],[
	AC_CHECK_FUNC(dlopen, [
			if test $ac_cv_func_dlopen = yes; then
			AC_DEFINE(HAVE_DLOPEN, 1, [Whether dlopen is available])
			fi
		], [
			AC_CHECK_FUNC(LoadLibrary, [
				if test $ac_cv_func_LoadLibrary = yes; then
					AC_DEFINE(HAVE_LOADLIBRARY, 1, [Whether LoadLibrary is available])
				fi
			], [
				AC_MSG_ERROR(No dynamic library loading support)
			])
		])
])
