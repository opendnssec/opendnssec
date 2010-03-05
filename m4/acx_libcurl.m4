# $Id: acx_libcurl.m4 2929 2010-03-02 13:01:39Z jakob $

AC_DEFUN([ACX_LIBCURL],[
	AC_ARG_WITH(sqlite3,
        	AC_HELP_STRING([--with-libcurl=PATH],[Specify prefix of path of libcurl]),
		[
			LIBCURL_PATH="$withval"
			
		],[
			LIBCURL_PATH="/usr/local"
		])
	
	AC_MSG_CHECKING(what are the CURL includes)
	CURL_INCLUDES="-I$LIBCURL_PATH/include"
	AC_MSG_RESULT($CURL_INCLUDES)

	AC_MSG_CHECKING(what are the CURL libs)
	CURL_LIBS="-L$LIBCURL_PATH/lib -lcurl"
	AC_MSG_RESULT($CURL_LIBS)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CURL_INCLUDES"
	LIBS="$LIBS $CURL_LIBS"

	AC_CHECK_HEADERS(curl/curl.h,,[AC_MSG_ERROR([Can't find libcurl headers])])
	AC_CHECK_LIB(curl, curl_version, [], [AC_MSG_ERROR([Missing libcurl library])])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(CURL_INCLUDES)
	AC_SUBST(CURL_LIBS)
])
