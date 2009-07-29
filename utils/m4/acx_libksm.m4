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

        ACX_ABS_SRCDIR # defines ac_sub_srcdir as an absolute path
        
	AC_CHECK_HEADERS(ksm/ksm.h,
	[
		AC_CHECK_LIB(ksm,KsmPolicyPopulateSMFromIds,,
		[
			AC_MSG_ERROR([libksm not found on system, and libksm source not present, use --with-libksm=path.])
		])
	],
	[
		# dnl ok we don't have an installed library, use the source
		# (makefile will figure it out)
		if test ! -f $ac_sub_srcdir/../../libksm/src/include/ksm/ksm.h; then
			if test ! -f $ac_sub_srcdir/../libksm/src/include/ksm/ksm.h; then
				AC_MSG_ERROR([libksm not found on system, and libksm source not present, use --with-libksm=path.])
			else
				LIBKSM_INCLUDES="$LIBKSM_INCLUDE -I$ac_sub_srcdir/../libksm/src/include -I../../libksm/src/include"
				LIBKSM_LIBS="$LIBKSM_LIBS -L../../libksm/src/.libs"
				BUILD_LIBKSM="../libksm"
			fi
		else
			LIBKSM_INCLUDES="$LIBKSM_INCLUDE -I$ac_sub_srcdir/../../libksm/src/include -I../../libksm/src/include"
			LIBKSM_LIBS="$LIBKSM_LIBS -L../../../libksm/src/.libs"
			BUILD_LIBKSM="../libksm"
		fi
	])


	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(BUILD_LIBKSM)
	AC_SUBST(LIBKSM_INCLUDES)
	AC_SUBST(LIBKSM_LIBS)
])
