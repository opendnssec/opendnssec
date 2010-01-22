# $Id: acx_sqlite3.m4 1543 2009-08-10 11:15:52Z jakob $

AC_DEFUN([ACX_SQLITE3],[
	CHECK_SQLITE_BIN=$1

	AC_ARG_WITH(sqlite3,
        	AC_HELP_STRING([--with-sqlite3=PATH],[Specify prefix of path of SQLite3]),
		[
			SQLITE3_PATH="$withval"
			if test "x$CHECK_SQLITE_BIN" != "x0"; then
				AC_PATH_PROGS(SQLITE3, sqlite3, sqlite3, $withval/bin)
			fi
			
		],[
			SQLITE3_PATH="/usr/local"
			if test "x$CHECK_SQLITE_BIN" != "x0"; then
				AC_PATH_PROGS(SQLITE3, sqlite3, sqlite3, $PATH)
			fi
		])
	
	if test "x$CHECK_SQLITE_BIN" != "x0"; then
		if ! test -x "$SQLITE3"; then
			AC_MSG_ERROR([sqlite3 command not found])
		fi
	fi
	
	AC_MSG_CHECKING(what are the SQLite3 includes)
	SQLITE3_INCLUDES="-I$SQLITE3_PATH/include"
	AC_MSG_RESULT($SQLITE3_INCLUDES)

	AC_MSG_CHECKING(what are the SQLite3 libs)
	SQLITE3_LIBS="-L$SQLITE3_PATH/lib -lsqlite3"
	AC_MSG_RESULT($SQLITE3_LIBS)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $SQLITE3_INCLUDES"
	LIBS="$LIBS $SQLITE3_LIBS"

	AC_CHECK_HEADERS(sqlite3.h,,[AC_MSG_ERROR([Can't find SQLite3 headers])])
	AC_CHECK_LIB(sqlite3, sqlite3_prepare_v2, [], [AC_MSG_ERROR([Missing SQLite3 library v3.4.2 or greater])])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(SQLITE3_INCLUDES)
	AC_SUBST(SQLITE3_LIBS)
])
