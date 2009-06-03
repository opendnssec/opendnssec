# $Id$

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(libksm, 0.0.1, jad@jadickinson.co.uk)
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/ksm_key.c])
# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PATH_PROG(PERL, perl)
if test -z "$PERL"; then
   AC_MSG_ERROR([perl not found])
fi

ACX_PEDANTIC
ACX_STRICT

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
AC_REPLACE_FUNCS(strlcat)
AC_REPLACE_FUNCS(strlcpy)

# Check for mysql
AC_ARG_WITH(mysql,
[  --with-mysql=DIR        Look for mysql in this dir ],
  [ MYSQL_PATH="$withval"],
 [ with_mysql=no ]
)
# Check for sqlite3
AC_ARG_WITH(sqlite3,
[  --with-sqlite3=DIR      Look for sqlite3 in this dir ],
   SQLITE_PATH="$withval"
)
if test "x$with_mysql" = "xno"; then
  DB_TYPE="SQLITE3"
  if test "x$SQLITE_PATH" != "x"
  then
     AC_MSG_CHECKING(what are the sqlite3 includes)
     DB_INCLUDES="-I$SQLITE_PATH/include -DUSE_SQLITE"
     AC_MSG_RESULT($DB_INCLUDES)
     AC_MSG_CHECKING(what are the sqlite3 libs)
     DB_LIBS="-L$SQLITE_PATH/lib -lsqlite3"
     AC_MSG_RESULT($DB_LIBS)
     AC_PATH_PROG(SQLITE3, sqlite3, $SQLITE_PATH/bin)
  else
      AC_MSG_CHECKING(what are the sqlite3 includes)
      DB_INCLUDES="-I/usr/local/include -DUSE_SQLITE"
      AC_MSG_RESULT($DB_INCLUDES)
      AC_MSG_CHECKING(what are the sqlite3 libs)
      DB_LIBS="-L/usr/local/lib -lsqlite3"
      AC_MSG_RESULT($DB_LIBS)
      AC_PATH_PROG(SQLITE3, sqlite3, /usr/local/bin)
  fi
else
  DB_TYPE="MYSQL"
  if test "x$MYSQL_PATH" = "x"; then
     AC_PATH_PROGS(MYSQL_CONFIG, mysql_config, mysql_config, $PATH)
     AC_PATH_PROG(MYSQL, mysql)
  else
     AC_PATH_PROGS(MYSQL_CONFIG, mysql_config, mysql_config, $MYSQL_PATH/bin)
     AC_PATH_PROG(MYSQL, mysql, ,$MYSQL_PATH/bin)
  fi
  if test -z "$MYSQL"; then
     AC_MSG_ERROR([mysql not found])
  fi
  if test -x "$MYSQL_CONFIG"
  then
  AC_MSG_CHECKING(mysql version)
  MYSQL_VERSION="`$MYSQL_CONFIG --version`"
  AC_MSG_RESULT($MYSQL_VERSION)
  if test ${MYSQL_VERSION//.*/} -le 4 ; then
       AC_MSG_ERROR([mysql must be newer than 5.0.0])
  fi

     AC_MSG_CHECKING(what are the mysql includes)
     # MySQL v4 uses --include while v3 uses --cflags
     DB_INCLUDES="`$MYSQL_CONFIG --include` -DBIG_JOINS=1 -DUSE_MYSQL" || \
         DB_INCLUDES="`$MYSQL_CONFIG --cflags`"
     AC_MSG_RESULT($DB_INCLUDES)
     AC_MSG_CHECKING(what are the mysql libs)
     DB_LIBS="`$MYSQL_CONFIG --libs_r`"
     AC_MSG_RESULT($DB_LIBS)
  fi
fi

AM_CONDITIONAL([MYSQL], [test "x$with_mysql" != "xno"]) 
AC_SUBST(DB_INCLUDES)
AC_SUBST(DB_LIBS)
AC_SUBST(DB_TYPE)

ACX_CUNIT

AC_ARG_WITH(dbname,
[  --with-dbname=DB_NAME   Database name/schema for unit tests  ],
   DB_NAME="$withval"
)
AC_SUBST(DB_NAME)

AC_ARG_WITH(dbhost,
[  --with-dbhost=DB_HOST   Database host for unit tests  ],
   DB_HOST="$withval"
)
AC_SUBST(DB_HOST)

AC_ARG_WITH(dbpass,
[  --with-dbpass=DB_PASS   Database host for unit tests  ],
   DB_PASS="$withval"
)
AC_SUBST(DB_PASS)

AC_ARG_WITH(dbuser,
[  --with-dbuser=DB_USER   Database host for unit tests  ],
   DB_USER="$withval"
)
AC_SUBST(DB_USER)

AH_BOTTOM([
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif           
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif
])

opendnssecsysconf="\$(sysconfdir)/opendnssec"
ksmdatadir="\$(datadir)/opendnssec"
ksmincludedir="\$(includedir)/ksm"

AC_SUBST([opendnssecsysconf])
AC_SUBST([ksmdatadir])
AC_SUBST([ksmincludedir])

AC_CONFIG_FILES([
Makefile
src/Makefile
src/include/Makefile
src/include/ksm/Makefile
utils/Makefile
test/Makefile
])

AC_CONFIG_HEADER([src/include/ksm/config.h])
AC_OUTPUT
