# $Id$

AC_DEFUN([ACX_LIBXML2],[
	AC_ARG_WITH(libxml2,
		[AS_HELP_STRING([--with-libxml2=DIR],[look for libxml2 in this dir])],
        	[
			XML2_PATH="$withval"
			AC_PATH_PROGS(XML2_CONFIG, xml2-config, xml2-config, $XML2_PATH/bin)
		],[
			XML2_PATH="/usr/local"
			AC_PATH_PROGS(XML2_CONFIG, xml2-config, xml2-config, $PATH)
		])
	if test -x "$XML2_CONFIG"
	then
		AC_MSG_CHECKING(what are the xml2 includes)
		XML2_INCLUDES="`$XML2_CONFIG --cflags`"
		AC_MSG_RESULT($XML2_INCLUDES)

		AC_MSG_CHECKING(what are the xml2 libs)
		XML2_LIBS="`$XML2_CONFIG --libs`"
		AC_MSG_RESULT($XML2_LIBS)

		tmp_CPPFLAGS=$CPPFLAGS
		tmp_LIBS=$LIBS

		CPPFLAGS="$CPPFLAGS $XML2_INCLUDES"
		LIBS="$LIBS $XML2_LIBS"

		AC_CHECK_LIB(xml2, xmlDocGetRootElement,,[AC_MSG_ERROR([Can't find libxml2 library])])
		
		CPPFLAGS=$tmp_CPPFLAGS
		LIBS=$tmp_LIBS
	else
		AC_MSG_ERROR([libxml2 required, but not found.])
	fi

	AC_SUBST(XML2_INCLUDES)
	AC_SUBST(XML2_LIBS)
])
