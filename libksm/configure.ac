#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(libksm, 0.0.1, jad@jadickinson.co.uk)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/ksm_key.c])
AC_CONFIG_HEADER([config.h])
# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([limits.h stdint.h stdlib.h string.h strings.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([localtime_r memset strdup strerror strstr strtol strtoul])

# Check for mysql
AC_ARG_WITH(mysql,
[  --with-mysql=DIR     Look for mysql in this dir ],
   MYSQL_PATH="$withval"
)
if test "x$MYSQL_PATH" = "x"; then
   AC_PATH_PROGS(MYSQL_CONFIG, mysql_config, mysql_config, $PATH)
else
   AC_PATH_PROGS(MYSQL_CONFIG, mysql_config, mysql_config, $MYSQL_PATH/bin)
fi
if test -x "$MYSQL_CONFIG"
then
   AC_MSG_CHECKING(what are the mysql includes)
   # MySQL v4 uses --include while v3 uses --cflags
   DB_INCLUDES="`$MYSQL_CONFIG --include` -DBIG_JOINS=1 -DUSE_MYSQL" || \
       DB_INCLUDES="`$MYSQL_CONFIG --cflags`"
   AC_MSG_RESULT($DB_INCLUDES)
   AC_MSG_CHECKING(what are the mysql libs)
   DB_LIBS="`$MYSQL_CONFIG --libs_r`"
   AC_MSG_RESULT($DB_LIBS)
fi
# Check for sqlite3
AC_ARG_WITH(sqlite3,
[  --with-sqlite3=DIR     Look for sqlite3 in this dir ],
   SQLITE_PATH="$withval"
)
if test "x$SQLITE_PATH" != "x"
then
   AC_MSG_CHECKING(what are the sqlite3 includes)
   DB_INCLUDES="-I$SQLITE_PATH/include -DUSE_SQLITE"
   AC_MSG_RESULT($DB_INCLUDES)
   AC_MSG_CHECKING(what are the sqlite3 libs)
   DB_LIBS="-L$SQLITE_PATH/lib -lsqlite3"
   AC_MSG_RESULT($DB_LIBS)
fi
AM_CONDITIONAL([MYSQL], [test x$MYSQL_PATH != "x"]) 
AC_SUBST(DB_INCLUDES)
AC_SUBST(DB_LIBS)

AC_CONFIG_FILES([
Makefile
include/Makefile
src/Makefile
])

AC_OUTPUT
