# $Id$

AC_DEFUN([ACX_LIBKSM],[
	AC_ARG_WITH(libksm, 
        	AC_HELP_STRING([--with-libksm=PATH],[Specify prefix of path of libksm]),
        	[
			LIBKSM_PATH="$withval"
		],[
			LIBKSM_PATH="/usr/local"
		])

	AC_MSG_CHECKING(what are the libksm includes)
	LIBKSM_INCLUDES="-I$LIBKSM_PATH/include"
	AC_MSG_RESULT($LIBKSM_INCLUDES)

	AC_MSG_CHECKING(what are the libksm libs)
	LIBKSM_LIBS="-L$LIBKSM_PATH/lib -lksm"
	AC_MSG_RESULT($LIBKSM_INCLUDES)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $LIBKSM_INCLUDES"
	LIBS="$LIBS $LIBKSM_LIBS"

	#AC_CHECK_HEADER(ksm/ksm.h,,[AC_MSG_ERROR([Can't find libksm headers:(])])
	AC_CHECK_LIB(ksm,KsmPolicyPopulateSMFromIds,,[AC_MSG_ERROR([Can't find libksm library])])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(LIBKSM_INCLUDES)
	AC_SUBST(LIBKSM_LIBS)
])
