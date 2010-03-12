# $Id: acx_database_backend.m4 3015 2010-03-11 15:42:46Z jakob $

AC_DEFUN([ACX_DATABASE_BACKEND],[

	AC_ARG_WITH(database-backend,
	        AC_HELP_STRING([--with-database-backend],
	                [Select database backend (sqlite3|mysql)]),
			[database_backend="${withval}"],
			[database_backend="sqlite3"])

	AC_MSG_CHECKING(for database backend)

	if test "x${database_backend}" = "xsqlite3"; then
		AC_MSG_RESULT(SQLite3)

		ACX_SQLITE3

		DB_TYPE=sqlite3 
		DB_INCLUDES=$SQLITE3_INCLUDES 
		DB_LIBS=$SQLITE3_LIBS 

		AC_DEFINE_UNQUOTED(SQL_BIN, "$SQLITE3", [database binary]) 
		AC_DEFINE_UNQUOTED(SQL_SETUP, "$OPENDNSSEC_DATA_DIR/database_create.sqlite3", [database setup script])

	elif test "x${database_backend}" = "xmysql"; then
		AC_MSG_RESULT(MySQL)

		ACX_MYSQL

	    	DB_TYPE=mysql
		DB_INCLUDES=$MYSQL_INCLUDES
		DB_LIBS=$MYSQL_LIBS

	        AC_DEFINE_UNQUOTED(SQL_BIN, "$MYSQL", [database binary]) 
		AC_DEFINE_UNQUOTED(SQL_SETUP, "$OPENDNSSEC_DATA_DIR/database_create.mysql", [database setup script])
	else
		AC_MSG_RESULT(Unknown)
		AC_MSG_ERROR([Database backend ${database_backend} not supported.])
	fi

	AC_SUBST(DB_TYPE) 
	AC_SUBST(DB_INCLUDES) 
	AC_SUBST(DB_LIBS) 

	AM_CONDITIONAL([USE_MYSQL], [test "x${database_backend}" = "xmysql"])
])
