# $Id$

AC_DEFUN([ACX_DBPARAMS],[

	AC_ARG_WITH(dbname,
		[AS_HELP_STRING([--with-dbname=DB_NAME],[Database name/schema for unit tests])],
		DB_NAME="$withval"
	)
	AC_SUBST(DB_NAME)
	
	AC_ARG_WITH(dbhost,
		[AS_HELP_STRING([--with-dbhost=DB_HOST],[Database host for unit tests])],
		DB_HOST="$withval"
	)
	AC_SUBST(DB_HOST)

	AC_ARG_WITH(dbport,
		[AS_HELP_STRING([--with-dbport=DB_PORT],[Database port for unit tests])],
		DB_PORT="$withval"
	)
	AC_SUBST(DB_PORT)
	
	AC_ARG_WITH(dbuser,
		[AS_HELP_STRING([--with-dbuser=DB_USER],[Database user for unit tests])],
		DB_USER="$withval"
	)
	AC_SUBST(DB_USER)
	
	AC_ARG_WITH(dbpass,
		[AS_HELP_STRING([--with-dbpass=DB_PASS],[Database password for unit tests])],
		DB_PASS="$withval"
	)
	AC_SUBST(DB_PASS)
])
