AC_DEFUN([ACX_CUNIT],[
	AC_ARG_WITH(cunit,
		[AS_HELP_STRING([--with-cunit=DIR],[Look for cunit in this dir])],
        	[
			CUNIT_PATH="$withval"
		],[
			CUNIT_PATH="/usr/local"
		])

	AS_IF([test "x$with_cunit" != xno],[

	AC_MSG_CHECKING(what are the cunit includes)
	CUNIT_INCLUDES="-I$CUNIT_PATH/include"
	AC_MSG_RESULT($CUNIT_INCLUDES)

	AC_MSG_CHECKING(what are the cunit libs)
	CUNIT_LIBS="-L$CUNIT_PATH/lib -lcunit"
	AC_MSG_RESULT($CUNIT_LIBS)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CUNIT_INCLUDES"
	LIBS="$LIBS $CUNIT_LIBS"

	AC_CHECK_LIB(cunit, CU_run_test, [],[
		AC_MSG_NOTICE([Can't find cunit library])
		CUNIT_INCLUDES=
		CUNIT_LIBS=
	])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	],[
		AC_MSG_NOTICE([cunit disabled])
		CUNIT_INCLUDES=
		CUNIT_LIBS=
	])

	AC_SUBST(CUNIT_INCLUDES)
	AC_SUBST(CUNIT_LIBS)
])
