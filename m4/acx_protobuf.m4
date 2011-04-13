# $Id$

AC_DEFUN([ACX_PROTOBUF],[
    PKG_CONFIG_WHICH="`which pkg-config`"
    AC_PATH_PROGS(PKG_CONFIG, pkg-config, $PKG_CONFIG_WHICH, /usr/local/bin)
	if test -x "$PKG_CONFIG"
	then
		AC_MSG_CHECKING(what are the PROTOBUF includes)
		PROTOBUF_INCLUDES="`$PKG_CONFIG --cflags protobuf`"
		AC_MSG_RESULT($PROTOBUF_INCLUDES)

		AC_MSG_CHECKING(what are the PROTOBUF libs)
		PROTOBUF_LIBS="`$PKG_CONFIG --libs protobuf`"
		AC_MSG_RESULT($PROTOBUF_LIBS)

		tmp_CPPFLAGS=$CPPFLAGS
		tmp_LIBS=$LIBS

		CPPFLAGS="$CPPFLAGS $PROTOBUF_INCLUDES"
		LIBS="$LIBS $PROTOBUF_LIBS"
		
		CPPFLAGS=$tmp_CPPFLAGS
		LIBS=$tmp_LIBS
	else
		AC_MSG_ERROR([pkg-config required, but not found.])
	fi

	AC_SUBST(PROTOBUF_INCLUDES)
	AC_SUBST(PROTOBUF_LIBS)
])
