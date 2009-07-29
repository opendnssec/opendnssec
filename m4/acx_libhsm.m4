# $Id$

AC_DEFUN([ACX_LIBHSM],[
	AC_ARG_WITH(libhsm, 
        	AC_HELP_STRING([--with-libhsm=PATH],[Specify prefix of path of libhsm]),
        	[
			LIBHSM_PATH="$withval"
		],[
			LIBHSM_PATH="/usr/local"
		])

	AC_MSG_CHECKING(what are the libhsm includes)
	LIBHSM_INCLUDES="-I$LIBHSM_PATH/include"
	AC_MSG_RESULT($LIBHSM_INCLUDES)

	AC_MSG_CHECKING(what are the libhsm libs)
	LIBHSM_LIBS="-L$LIBHSM_PATH/lib -lhsm"
	AC_MSG_RESULT($LIBHSM_INCLUDES)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $XML2_INCLUDES $LIBHSM_INCLUDES"
	LIBS="$LIBS -L$LIBHSM_PATH/lib"

	BUILD_LIBHSM=""

	case "$srcdir" in
	.) # No --srcdir option.  We are building in place.
		ac_sub_srcdir=`pwd` ;;
	/*) # Absolute path.
		ac_sub_srcdir=$srcdir/$ac_config_dir ;;
	*) # Relative path.
		ac_sub_srcdir=$ac_dots$srcdir/$ac_config_dir ;;
	esac

	AC_CHECK_HEADERS(libhsm.h,
	[
		AC_CHECK_LIB(hsm,hsm_create_context,,
		[
			AC_MSG_ERROR([libhsm not found on system, and libhsm source not present, use --with-libhsm=path.])
		])
	],
	[
		# dnl ok we don't have an installed library, use the source
		# (makefile will figure it out)
		if test ! -f $ac_sub_srcdir/../../libhsm/src/libhsm.h; then
			if test ! -f $ac_sub_srcdir/../libhsm/src/libhsm.h; then
				AC_MSG_ERROR([libhsm not found on system, and libhsm source not present, use --with-libhsm=path.])
			else
				LIBHSM_INCLUDES="$LIBHSM_INCLUDE -I$ac_sub_srcdir/../libhsm/src"
				LIBHSM_LIBS="$LIBHSM_LIBS -L../../libhsm/src/.libs"
				BUILD_LIBHSM="../libhsm"
			fi
		else
			LIBHSM_INCLUDES="$LIBHSM_INCLUDE -I$ac_sub_srcdir/../../libhsm/src"
			LIBHSM_LIBS="$LIBHSM_LIBS -L../../../libhsm/src/.libs"
			BUILD_LIBHSM="../libhsm"
		fi
	])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(BUILD_LIBHSM)
	AC_SUBST(LIBHSM_INCLUDES)
	AC_SUBST(LIBHSM_LIBS)
])
