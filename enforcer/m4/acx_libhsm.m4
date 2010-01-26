# $Id$

AC_DEFUN([ACX_LIBHSM],[
	AC_ARG_WITH(libhsm, 
        	AC_HELP_STRING([--with-libhsm=PATH],[Specify prefix of path of libhsm]),
        	[
			LIBHSM_PATH="$withval"
		],[
			LIBHSM_PATH="/usr/local"
		])

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	BUILD_LIBHSM=""

	ACX_ABS_SRCDIR # defines ac_sub_srcdir as an absolute path
	
	if test -f ../libhsm/config.h; then
		AC_MSG_NOTICE([using libhsm from source tree])
		LIBHSM_INCLUDES="-I$ac_sub_srcdir/../libhsm/src"
		LIBHSM_LIBS="-L../../libhsm/src/.libs -lhsm"
		BUILD_LIBHSM="../../libhsm/src/libhsm.la"
	else
		AC_MSG_NOTICE([no libhsm in source tree, looking elsewhere])
	
		AC_MSG_CHECKING(what are the libhsm includes)
		LIBHSM_INCLUDES="-I$LIBHSM_PATH/include"
		AC_MSG_RESULT($LIBHSM_INCLUDES)

		AC_MSG_CHECKING(what are the libhsm libs)
		LIBHSM_LIBS="-L$LIBHSM_PATH/lib -lhsm"
		AC_MSG_RESULT($LIBHSM_LIBS)

		CPPFLAGS="$CPPFLAGS $XML2_INCLUDES $LIBHSM_INCLUDES"
		LIBS="$LIBS -L$LIBHSM_PATH/lib"

		AC_CHECK_HEADERS(libhsm.h, [
			AC_CHECK_LIB(hsm,hsm_create_context,, [
				AC_MSG_ERROR([libhsm not found on system and libhsm source not present; use --with-libhsm=path])
				])
		], [
			AC_MSG_ERROR([libhsm not found in source tree nor on system])
		])
	fi

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(BUILD_LIBHSM)
	AC_SUBST(LIBHSM_INCLUDES)
	AC_SUBST(LIBHSM_LIBS)
])
