# $Id$

AC_DEFUN([AM_PROG_RUBY],[
	RUBY_PROGS="ruby ruby1.9 ruby1.8 ruby1.7 ruby1.6"
	AC_ARG_WITH(ruby,
		[AC_HELP_STRING([--with-ruby=PATH],[specify ruby interpreter (e.g. ruby1.9)])],
		[
			AC_MSG_CHECKING([for ruby])
			AC_SUBST([RUBY], ["$withval"])
			AC_MSG_RESULT([$withval])
		],[
			AC_PATH_PROGS([RUBY], [$RUBY_PROGS], [:])
		])

	if test "$RUBY" = ":"
	then
		AC_MSG_ERROR([ruby interpreter was not found, tried "$RUBY_PROGS"])
	fi
	])
