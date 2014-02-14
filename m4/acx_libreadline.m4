# $Id$

AC_DEFUN([ACX_LIBREADLINE],[
	AC_ARG_WITH(readline,
		[  --with-readline         compile with the system readline library],
		[if test x"${withval}" != no; then
			AC_CHECK_LIB(readline, readline,
				if test x"${ac_cv_lib_readline_readline}" = xno; then
				AC_MSG_ERROR(libreadline not found)
				fi
				AC_SUBST(READLINE_LIBS, "-lreadline")
				AC_DEFINE([HAVE_READLINE], [1], [Define to 1 if readline libraries are available])
			,)
		fi])
])
