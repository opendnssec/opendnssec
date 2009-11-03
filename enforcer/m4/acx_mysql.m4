# $Id$

AC_DEFUN([ACX_MYSQL],[
	AC_ARG_WITH(mysql,
        	AC_HELP_STRING([--with-mysql=DIR],[Specify prefix of path of MySQL]),
		[
			MYSQL_PATH="$withval"
			AC_PATH_PROGS(MYSQL_CONFIG, mysql_config, mysql_config, $MYSQL_PATH/bin)
			AC_PATH_PROGS(MYSQL, mysql, mysql, $MYSQL_PATH/bin)
		],[])

	if test -d "$MYSQL_PATH"; then
		if test -x "$MYSQL_CONFIG"; then
			AC_MSG_CHECKING(mysql version)
			MYSQL_VERSION="`$MYSQL_CONFIG --version`"
			AC_MSG_RESULT($MYSQL_VERSION)
			if test ${MYSQL_VERSION//.*/} -le 4 ; then
				AC_MSG_ERROR([mysql must be newer than 5.0.0])
			fi
	
			AC_MSG_CHECKING(what are the MySQL includes)
			MYSQL_INCLUDES="`$MYSQL_CONFIG --include` -DBIG_JOINS=1 -DUSE_MYSQL"
			AC_MSG_RESULT($MYSQL_INCLUDES)
	
			AC_MSG_CHECKING(what are the MySQL libs)
			MYSQL_LIBS="`$MYSQL_CONFIG --libs_r`"
			AC_MSG_RESULT($MYSQL_LIBS)
	  	fi

		if ! test -x "$MYSQL"; then
			AC_MSG_ERROR([mysql command not found])
		fi
	fi

	AC_SUBST(MYSQL_INCLUDES)
	AC_SUBST(MYSQL_LIBS)
])
