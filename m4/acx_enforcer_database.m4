# $Id$

AC_DEFUN([ACX_ENFORCER_DATABASE],[

	AC_ARG_WITH(enforcer-database,
	        AC_HELP_STRING([--with-enforcer-database],
	                [Select database backend (sqlite3|dbi)]),
			[database_backend="${withval}"],
			[database_backend="sqlite3"])

	AC_MSG_CHECKING(for database backend)

	if test "x${database_backend}" = "xsqlite3"; then
		AC_MSG_RESULT(SQLite3)

		ACX_SQLITE3

		DB_TYPE=sqlite3
		DB_INCLUDES=$SQLITE3_INCLUDES
		DB_LIBS=$SQLITE3_LIBS

		AC_DEFINE_UNQUOTED(ENFORCER_DATABASE_SQLITE3, 1, [Using SQLite3 for database backend])

#	elif test "x${database_backend}" = "xmysql"; then
#		AC_MSG_RESULT(MySQL)
#
#		ACX_MYSQL
#
#	    	DB_TYPE=mysql
#		DB_INCLUDES=$MYSQL_INCLUDES
#		DB_LIBS=$MYSQL_LIBS
#
#		AC_DEFINE_UNQUOTED(ENFORCER_DATABASE_MYSQL, 1, [Using MySQL for database backend])

	elif test "x${database_backend}" = "xdbi"; then
		AC_MSG_RESULT(DBI)

		# ACX_DBI

	    	DB_TYPE=dbi
		DB_INCLUDES=$DBI_INCLUDES
		DB_LIBS=$DBI_LIBS

		AC_DEFINE_UNQUOTED(ENFORCER_DATABASE_DBI, 1, [Using DBI for database backend])

	else
		AC_MSG_RESULT(Unknown)
		AC_MSG_ERROR([Database backend ${database_backend} not supported.])
	fi

	AC_SUBST(DB_TYPE) 
	AC_SUBST(DB_INCLUDES) 
	AC_SUBST(DB_LIBS) 
])
