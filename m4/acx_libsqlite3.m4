AC_DEFUN([ACX_LIBSQLITE3],[
	
	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS
	
	AC_ARG_WITH(sqlite3,
        	AC_HELP_STRING([--with-sqlite3=PATH],[Specify prefix of path of SQLite3]),
		[SQLITE3_PATH="$withval"],[])
	
	dnl Actually check if the user specified path points to sqlite3.h
	AS_IF([test "x$SQLITE3_PATH" != "x" && test -e "$SQLITE3_PATH/include/sqlite3.h"],
		[SQLITE3_INCLUDES="-I$SQLITE3_PATH/include"],
		[SQLITE3_INCLUDES=""]
	)
	CPPFLAGS="$CPPFLAGS $SQLITE3_INCLUDES"
	AC_CHECK_HEADER(sqlite3.h,,[AC_MSG_ERROR([Can't find SQLite3 headers])])

	dnl Actually check if the user specified path points to libsqlite3.*
	AS_IF([test "x$SQLITE3_PATH" != "x" && (test -e "$SQLITE3_PATH/lib/libsqlite3.so" || test -e "$SQLITE3_PATH/lib/libsqlite3.dylib")],
		[SQLITE3_LIBS="-L$SQLITE3_PATH/lib -lsqlite3"],
		[SQLITE3_LIBS="-lsqlite3"]
	)
	LIBS="$LIBS $SQLITE3_LIBS"
	AC_CHECK_LIB(sqlite3, sqlite3_prepare_v2, [], [AC_MSG_ERROR([Missing SQLite3 library v3.3.9 or greater])])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(SQLITE3_INCLUDES)
	AC_SUBST(SQLITE3_LIBS)
])
