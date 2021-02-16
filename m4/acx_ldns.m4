AC_DEFUN([ACX_LDNS],[
	AC_ARG_WITH(ldns, 
		[AS_HELP_STRING([--with-ldns=PATH],[specify prefix of path of ldns library to use])],
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

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $LDNS_INCLUDES"
	LIBS="$LIBS $LDNS_LIBS"

	AC_CHECK_LIB(ldns, ldns_rr_new,,[AC_MSG_ERROR([Can't find ldns library])])
	LIBS=$tmp_LIBS

	AC_MSG_CHECKING([for ldns version])
	CHECK_LDNS_VERSION=m4_format(0x%02x%02x%02x, $1, $2, $3)
	AC_LANG_PUSH([C])
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <ldns/ldns.h>
			int main()
			{
			#ifdef LDNS_REVISION
				if (LDNS_REVISION >= $CHECK_LDNS_VERSION)
					return 0;
			#endif
				return 1;
			}
		]])
	],[
		AC_MSG_RESULT([>= $1.$2.$3])
	],[
		AC_MSG_RESULT([< $1.$2.$3])
		AC_MSG_ERROR([ldns library too old ($1.$2.$3 or later required)])
	],[])
	AC_LANG_POP([C])

	CPPFLAGS=$tmp_CPPFLAGS

	AC_SUBST(LDNS_INCLUDES)
	AC_SUBST(LDNS_LIBS)
])


AC_DEFUN([ACX_LDNS_NOT],[
	AC_ARG_WITH(ldns, 
		[AS_HELP_STRING([--with-ldns=PATH],[specify prefix of path of ldns library to use])],
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

	tmp_CPPFLAGS=$CPPFLAGS

	CPPFLAGS="$CPPFLAGS $LDNS_INCLUDES"

	AC_MSG_CHECKING([for ldns version not $1.$2.$3])
	CHECK_LDNS_VERSION=m4_format(0x%02x%02x%02x, $1, $2, $3)
	AC_LANG_PUSH([C])
	AC_RUN_IFELSE([
	AC_LANG_SOURCE([[
		#include <ldns/ldns.h>
		int main()
		{
		#ifdef LDNS_REVISION
			if (LDNS_REVISION != $CHECK_LDNS_VERSION)
				return 0;
		#endif
			return 1;
		}
		]])
	],[
		AC_MSG_RESULT([ok])
	],[
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([ldns version $1.$2.$3 is not compatible due to $4])
	],[])
	AC_LANG_POP([C])

	CPPFLAGS=$tmp_CPPFLAGS
])
