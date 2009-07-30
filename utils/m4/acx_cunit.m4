# $Id$

AC_DEFUN([ACX_CUNIT],[
	AC_ARG_WITH(cunit,
		[AC_HELP_STRING([--with-cunit=DIR],[Look for cunit in this dir])],
        	[
			CUNIT_PATH="$withval"
		],[
			CUNIT_PATH="/usr/local"
		])

	AC_MSG_CHECKING(what are the cunit includes)
	CUNIT_INCLUDES="-I$CUNIT_PATH/include"
	AC_MSG_RESULT($CUNIT_INCLUDES)

	AC_MSG_CHECKING(what are the cunit libs)
	CUNIT_LIBS="-L$CUNIT_PATH/lib -lcunit"
	AC_MSG_RESULT($CUNIT_LIBS)

	AC_SUBST(CUNIT_INCLUDES)
	AC_SUBST(CUNIT_LIBS)
])
