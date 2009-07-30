# $Id$

AC_DEFUN([ACX_TRANG],[
	AC_ARG_WITH(trang,
		[AS_HELP_STRING([--with-trang],[Path to trang(.jar) (optional)])],
		TRANG="$withval"
	)

	if test "x$TRANG" != "x"; then
		if test -x $TRANG; then
			AC_MSG_NOTICE(trang will run like this $TRANG)
		elif test -e $TRANG; then
			# TRANG exists, let's assume it's a jar-file
			TRANG="$JAVA -jar $TRANG"
			AC_MSG_NOTICE(trang will run like this $TRANG)
		fi
	else
		AC_PATH_PROG(TRANG, trang)
	fi

	if test "x$TRANG" = "x"; then
		AC_MSG_NOTICE([trang.jar can be downloaded from http://code.google.com/p/jing-trang/])
	    	AC_MSG_ERROR(trang is needed to continue - say where it is with --with-trang=PATH)
	fi

	AC_SUBST(TRANG)
])
