# $Id$

AC_DEFUN([ACX_TRANG],[
	AC_ARG_WITH(trang,
		[AS_HELP_STRING([--with-trang],[Path to trang.jar (optional)])],
	   	TRANGJAR="$withval"
		)
	if test "x$TRANGJAR" != "x"
	then
		if test -e $TRANGJAR
		then
			TRANG="$JAVA -jar $TRANGJAR"
			AC_MSG_NOTICE(trang will run like this $TRANG)
	  	else
	    		AC_MSG_ERROR(trang.jar is needed to continue. Say where it is with --with-trang=PATH)
		fi
	else
		AC_MSG_NOTICE([trang.jar can be downloaded from http://code.google.com/p/jing-trang/])
		TRANG=
	fi
	AC_SUBST(TRANG)
])
