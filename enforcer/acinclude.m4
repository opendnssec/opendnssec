# $Id: acinclude.m4 885 2009-06-02 19:31:01Z jakob $

AC_DEFUN([ACX_PEDANTIC],[
	AC_ARG_ENABLE(
		[pedantic],
		[AS_HELP_STRING([--enable-pedantic],[enable pedantic compile mode @<:@enabled@:>@])],
		,
		[enable_pedantic="yes"]
	)
	if test "${enable_pedantic}" = "yes"; then
		enable_strict="yes";
		CFLAGS="${CFLAGS} -pedantic"
	fi
])

AC_DEFUN([ACX_STRICT],[
	AC_ARG_ENABLE(
		[strict],
		[AS_HELP_STRING([--enable-strict],[enable strict compile mode @<:@enabled@:>@])],
		,
		[enable_strict="yes"]
	)
	if test "${enable_strict}" = "yes"; then
		CFLAGS="${CFLAGS} -Wall -Wextra"
	fi
])

AC_DEFUN([ACX_LIBXML2],[
	AC_ARG_WITH(libxml2,
		[AS_HELP_STRING([--with-libxml2=DIR],[look for libxml2 in this dir])],
  		[XML_PATH="$withval"]
	)
	if test "x$XML_PATH" = "x"; then
		AC_PATH_PROGS(XML_CONFIG, xml2-config, xml2-config, $PATH)
	else
		AC_PATH_PROGS(XML_CONFIG, xml2-config, xml2-config, $XML_PATH/bin)
	fi
	if test -x "$XML_CONFIG"
	then
		XML_INCLUDES="`$XML_CONFIG --cflags`"
		XML_LIBS="`$XML_CONFIG --libs`"
	fi
	AC_SUBST(XML_INCLUDES)
	AC_SUBST(XML_LIBS)
])

AC_DEFUN([ACX_LDNS],[
	AC_ARG_WITH(ldns, 
		[AC_HELP_STRING([--with-ldns=PATH],[specify prefix of path of ldns library to use])],
		[
			CFLAGS="$CFLAGS -I$withval/include"
			LDFLAGS="-L$withval/lib $LDFLAGS"
		])
	AC_CHECK_LIB(ldns, ldns_rr_new,,[AC_MSG_ERROR([Can't find ldns library])])
	AC_CHECK_FUNC(ldns_sha1,[],[AC_MSG_ERROR([ldns library too old, please update it])])
	AC_SUBST(LDNS_INCLUDES)
	AC_SUBST(LDNS_LIBS)
])

AC_DEFUN([ACX_CUNIT],[
	AC_ARG_WITH(cunit,
		[AC_HELP_STRING([--cunit=DIR],[Look for cunit in this dir])],
   		CUNIT_PATH="$withval"
	)
	if test "x$CUNIT_PATH" != "x"
	then
		AC_MSG_CHECKING(what are the cunit includes)
		CUNIT_INCLUDES="-I$CUNIT_PATH/include"
		AC_MSG_RESULT($CUNIT_INCLUDES)
		AC_MSG_CHECKING(what are the cunit libs)
		CUNIT_LIBS="-L$CUNIT_PATH/lib -lcunit"
		AC_MSG_RESULT($CUNIT_LIBS)
	fi
	AC_SUBST(CUNIT_INCLUDES)
	AC_SUBST(CUNIT_LIBS)
])

AC_DEFUN([ACX_LIBHSM],[
	AC_ARG_WITH(libhsm, 
        	AC_HELP_STRING([--with-libhsm=PATH],[Specify prefix of path of libhsm]),
        	[
			CFLAGS="$CFLAGS -I$withval/include"
			LDFLAGS="-L$withval/lib $LDFLAGS"
		])
	AC_CHECK_HEADERS(libhsm.h,,[AC_MSG_ERROR([Can't find libhsm headers])])
	AC_CHECK_LIB(hsm,hsm_create_context,,[AC_MSG_ERROR([Can't find libhsm library])])
])

AC_DEFUN([ACX_LIBKSM],[
	AC_ARG_WITH(libksm, 
        	AC_HELP_STRING([--with-libksm=PATH],[Specify prefix of path of libksm]),
        	[
			CFLAGS="$CFLAGS -I$withval/include"
			LDFLAGS="-L$withval/lib $LDFLAGS"
		])
	AC_CHECK_HEADERS(ksm/ksm.h,,[AC_MSG_ERROR([Can't find libksm headers])])
	AC_CHECK_LIB(ksm,KsmPolicyPopulateSMFromIds,,[AC_MSG_ERROR([Can't find libksm library])])
])

dnl TODO
dnl
dnl ACX_MYSQL
dnl ACX_SQLITE3
dnl ACX_BOTAN
