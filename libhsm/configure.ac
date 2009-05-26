#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([libhsm],[0.0.1],[roy@dnss.ec])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([src/libhsm.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

AC_ARG_ENABLE(
	[strict],
	[AS_HELP_STRING([--enable-strict],[enable strict compile mode @<:@enabled@:>@])],
	,
	[enable_strict="yes"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AS_HELP_STRING([--enable-pedantic],[enable pedantic compile mode @<:@enabled@:>@])],
	,
	[enable_pedantic="yes"]
)

 
# Checks for libraries.
AC_CHECK_LIB([dl], [dlopen])
AC_CHECK_LIB([uuid], [uuid_generate])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([getpass getpassphrase memset])

# check for libxml
AC_ARG_WITH(libxml2,
[  --with-libxml2=DIR      look for libxml2 in this dir ],
  [ XML_PATH="$withval"]
)
  if test "x$XML_PATH" = "x"; then
     AC_PATH_PROGS(XML_CONFIG, xml2-config, xml2-config, $PATH)
  else
     AC_PATH_PROGS(XML_CONFIG, xml2-config, xml2-config, $XML_PATH/bin)
  fi
  if test -x "$XML_CONFIG"
  then
     #AC_MSG_CHECKING(what are the libxml2 includes)
     #XML_INCLUDES="`$XML_CONFIG --cflags`"
     #AC_MSG_RESULT($XML_INCLUDES)
     #AC_MSG_CHECKING(what are the libxml2 libs)
     #XML_LIBS="`$XML_CONFIG --libs`"
     #AC_MSG_RESULT($XML_LIBS)
	CFLAGS="$CFLAGS `$XML_CONFIG --cflags`"
	LDFLAGS="`$XML_CONFIG --libs` $LDFLAGS"
	XMLDIR="$withval"
  fi

# check for ldns in --with-ldns
AC_ARG_WITH(ldns, 
	AC_HELP_STRING([--with-ldns=PATH        specify prefix of path of ldns library to use])
	,
	[
		specialldnsdir="$withval"
		CFLAGS="$CFLAGS -I$withval/include"
		LDFLAGS="-L$withval/lib $LDFLAGS"
		LDNSDIR="$withval"
	]
)

# check for ldns on system
AC_CHECK_LIB(ldns, ldns_rr_new,, [
		AC_MSG_ERROR([Can't find ldns library])
	]
)

# check whether our linked ldns is actually recent enough
AC_CHECK_FUNC(ldns_b32_ntop, [], [
		AC_MSG_ERROR([ldns library too old, please update it])
	]
)

# check for dynamic loading library
AC_CHECK_FUNC(dlopen, 
[
	if test $ac_cv_func_dlopen = yes; then
	  AC_DEFINE(HAVE_DLOPEN, 1, [Whether dlopen is available])
	fi
], [
	AC_CHECK_FUNC(LoadLibrary, 
	[
		if test $ac_cv_func_LoadLibrary = yes; then
		  AC_DEFINE(HAVE_LOADLIBRARY, 1, [Whether LoadLibrary is available])
		fi
	], [
		AC_MSG_ERROR(No dynamic library loading support)
	])
])

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes";
	CFLAGS="${CFLAGS} -pedantic"
fi
if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wextra"
fi

AC_CONFIG_HEADERS([src/config.h])

AC_CONFIG_FILES([
Makefile
src/Makefile
checks/Makefile
])

AC_OUTPUT
