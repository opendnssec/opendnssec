# $Id$

AC_DEFUN([ACX_LDNS],[
	AC_ARG_WITH(ldns, 
		[AC_HELP_STRING([--with-ldns=PATH],[specify prefix of path of ldns library to use])],
        	[
			LDNS_PATH="$withval"
			AC_PATH_PROGS(LDNS_CONFIG, ldns-config, ldns-config, $LDNS_PATH/bin)
		],[
			LDNS_PATH="/usr/local"
			AC_PATH_PROGS(LDNS_CONFIG, ldns-config, ldns-config, $PATH)
		])

	if test -x "$LDNS_CONFIG"
	then
		AC_MSG_CHECKING(what are the ldns includes)
		LDNS_INCLUDES="`$LDNS_CONFIG --cflags`"
		AC_MSG_RESULT($LDNS_INCLUDES)

		AC_MSG_CHECKING(what are the ldns libs)
		LDNS_LIBS="`$LDNS_CONFIG --libs`"
		AC_MSG_RESULT($LDNS_LIBS)
	else
		AC_MSG_CHECKING(what are the ldns includes)
		LDNS_INCLUDES="-I$LDNS_PATH/include"
		AC_MSG_RESULT($LDNS_INCLUDES)

		AC_MSG_CHECKING(what are the ldns libs)
		LDNS_LIBS="-L$LDNS_PATH/lib -lldns"
		AC_MSG_RESULT($LDNS_LIBS)
	fi

	tmp_CPPFLAGS=$INCLUDES
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $LDNS_INCLUDES"
	LIBS="$LIBS $LDNS_LIBS"

	AC_CHECK_LIB(ldns, ldns_rr_new,,[AC_MSG_ERROR([Can't find ldns library])])
	AC_CHECK_FUNC(ldns_sha1,[],[AC_MSG_ERROR([ldns library too old (1.6.0 or later required)])])
	
	CPPFLAGS=$tmp_INCLUDES
	LIBS=$tmp_LIBS

	AC_SUBST(LDNS_INCLUDES)
	AC_SUBST(LDNS_LIBS)
])
