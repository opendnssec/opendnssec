# $Id$

AC_DEFUN([ACX_PEDANTIC],[
	AC_ARG_ENABLE(
		[pedantic],
		[AS_HELP_STRING([--enable-pedantic],[enable pedantic compile mode @<:@enabled@:>@])],
		,
		[enable_pedantic="yes"]
	)
	if test "${enable_pedantic}" = "yes"; then
		enable_strict="yes";
		CFLAGS="${CFLAGS} -pedantic"
	fi
])

AC_DEFUN([ACX_STRICT],[
	AC_ARG_ENABLE(
		[strict],
		[AS_HELP_STRING([--enable-strict],[enable strict compile mode @<:@enabled@:>@])],
		,
		[enable_strict="yes"]
	)
	if test "${enable_strict}" = "yes"; then
		CFLAGS="${CFLAGS} -Wall -Wextra"
	fi
])

AC_DEFUN([ACX_LIBXML2],[
	AC_ARG_WITH(libxml2,
		[AS_HELP_STRING([--with-libxml2=DIR],[look for libxml2 in this dir])],
        	[
			XML2_PATH="$withval"
			AC_PATH_PROGS(XML2_CONFIG, xml2-config, xml2-config, $XML2_PATH/bin)
		],[
			XML2_PATH="/usr/local"
			AC_PATH_PROGS(XML2_CONFIG, xml2-config, xml2-config, $PATH)
		])
	if test -x "$XML2_CONFIG"
	then
		AC_MSG_CHECKING(what are the xml2 includes)
		XML2_INCLUDES="`$XML2_CONFIG --cflags`"
		AC_MSG_RESULT($XML2_INCLUDES)

		AC_MSG_CHECKING(what are the xml2 libs)
		XML2_LIBS="`$XML2_CONFIG --libs`"
		AC_MSG_RESULT($XML2_LIBS)

		tmp_CPPFLAGS=$CPPFLAGS
		tmp_LIBS=$LIBS

		CPPFLAGS="$CPPFLAGS $XML2_INCLUDES"
		LIBS="$LIBS $XML2_LIBS"

		AC_CHECK_LIB(xml2, xmlDocGetRootElement,,[AC_MSG_ERROR([Can't find libxml2 library])])
		
		CPPFLAGS=$tmp_CPPFLAGS
		LIBS=$tmp_LIBS
	else
		AC_MSG_ERROR([libxml2 required, but not found.])
	fi

	AC_SUBST(XML2_INCLUDES)
	AC_SUBST(XML2_LIBS)
])

AC_DEFUN([ACX_LDNS],[
	AC_ARG_WITH(ldns, 
		[AC_HELP_STRING([--with-ldns=PATH],[specify prefix of path of ldns library to use])],
        	[
			LDNS_PATH="$withval"
		],[
			LDNS_PATH="/usr/local"
		])

	AC_MSG_CHECKING(what are the ldns includes)
	LDNS_INCLUDES="-I$LDNS_PATH/include"
	AC_MSG_RESULT($LDNS_INCLUDES)

	AC_MSG_CHECKING(what are the ldns libs)
	LDNS_LIBS="-L$LDNS_PATH/lib -lldns"
	AC_MSG_RESULT($LDNS_LIBS)

	tmp_CPPFLAGS=$INCLUDES
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $LDNS_INCLUDES"
	LIBS="$LIBS $LDNS_LIBS"

	AC_CHECK_LIB(ldns, ldns_rr_new,,[AC_MSG_ERROR([Can't find ldns library])])
	AC_CHECK_FUNC(ldns_sha1,[],[AC_MSG_ERROR([ldns library too old, please update it])])
	
	CPPFLAGS=$tmp_INCLUDES
	LIBS=$tmp_LIBS

	AC_SUBST(LDNS_INCLUDES)
	AC_SUBST(LDNS_LIBS)
])

AC_DEFUN([ACX_CUNIT],[
	AC_ARG_WITH(cunit,
		[AC_HELP_STRING([--with-cunit=DIR],[Look for cunit in this dir])],
        	[
			CUNIT_PATH="$withval"
		],[
			CUNIT_PATH="/usr/local"
		])

	AC_MSG_CHECKING(what are the cunit includes)
	CUNIT_INCLUDES="-I$CUNIT_PATH/include"
	AC_MSG_RESULT($CUNIT_INCLUDES)

	AC_MSG_CHECKING(what are the cunit libs)
	CUNIT_LIBS="-L$CUNIT_PATH/lib -lcunit"
	AC_MSG_RESULT($CUNIT_LIBS)

	AC_SUBST(CUNIT_INCLUDES)
	AC_SUBST(CUNIT_LIBS)
])

AC_DEFUN([ACX_LIBHSM],[
	AC_ARG_WITH(libhsm, 
        	AC_HELP_STRING([--with-libhsm=PATH],[Specify prefix of path of libhsm]),
        	[
			LIBHSM_PATH="$withval"
		],[
			LIBHSM_PATH="/usr/local"
		])

	AC_MSG_CHECKING(what are the libhsm includes)
	LIBHSM_INCLUDES="-I$LIBHSM_PATH/include"
	AC_MSG_RESULT($LIBHSM_INCLUDES)

	AC_MSG_CHECKING(what are the libhsm libs)
	LIBHSM_LIBS="-L$LIBHSM_PATH/lib -lhsm"
	AC_MSG_RESULT($LIBHSM_INCLUDES)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $XML2_INCLUDES $LIBHSM_INCLUDES"
	LIBS="$LIBS -L$LIBHSM_PATH/lib"

	AC_CHECK_HEADERS(libhsm.h,,[AC_MSG_ERROR([Can't find libhsm headers])])
	AC_CHECK_LIB(hsm,hsm_create_context,,[AC_MSG_ERROR([Can't find libhsm library])])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(LIBHSM_INCLUDES)
	AC_SUBST(LIBHSM_LIBS)
])

AC_DEFUN([ACX_LIBKSM],[
	AC_ARG_WITH(libksm, 
        	AC_HELP_STRING([--with-libksm=PATH],[Specify prefix of path of libksm]),
        	[
			LIBKSM_PATH="$withval"
		],[
			LIBKSM_PATH="/usr/local"
		])

	AC_MSG_CHECKING(what are the libksm includes)
	LIBKSM_INCLUDES="-I$LIBKSM_PATH/include"
	AC_MSG_RESULT($LIBKSM_INCLUDES)

	AC_MSG_CHECKING(what are the libksm libs)
	LIBKSM_LIBS="-L$LIBKSM_PATH/lib -lksm"
	AC_MSG_RESULT($LIBKSM_INCLUDES)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $LIBKSM_INCLUDES"
	LIBS="$LIBS $LIBKSM_LIBS"

	AC_CHECK_HEADERS(ksm/ksm.h,,[AC_MSG_ERROR([Can't find libksm headers])])
	AC_CHECK_LIB(ksm,KsmPolicyPopulateSMFromIds,,[AC_MSG_ERROR([Can't find libksm library])])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(LIBKSM_INCLUDES)
	AC_SUBST(LIBKSM_LIBS)
])

AC_DEFUN([ACX_SQLITE3],[
	AC_ARG_WITH(sqlite3,
        	AC_HELP_STRING([--with-sqlite3=PATH],[Specify prefix of path of SQLite3]),
		[
			SQLITE3_PATH="$withval"
			AC_PATH_PROG(SQLITE3, sqlite3, $withval/bin)
		],[
			SQLITE3_PATH="/usr/local"
			AC_PATH_PROG(SQLITE3, sqlite3, $PATH)
		])
	
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

AC_DEFUN([ACX_MYSQL],[
	AC_ARG_WITH(mysql,
        	AC_HELP_STRING([--with-mysql=DIR],[Specify prefix of path of MySQL]),
		[
			MYSQL_PATH="$withval"
			AC_PATH_PROGS(MYSQL_CONFIG, mysql_config, mysql_config, $MYSQL_PATH/bin)
			AC_PATH_PROG(MYSQL, mysql, ,$MYSQL_PATH/bin)
		],[
			MYSQL_PATH="/usr/local"
			AC_PATH_PROGS(MYSQL_CONFIG, mysql_config, mysql_config, $PATH)
			AC_PATH_PROG(MYSQL, mysql)
		])
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

		AC_MSG_CHECKING(what are the MySQL includes)
		MYSQL_INCLUDES="`$MYSQL_CONFIG --include` -DBIG_JOINS=1 -DUSE_MYSQL"
		AC_MSG_RESULT($MYSQL_INCLUDES)

		AC_MSG_CHECKING(what are the MySQL libs)
		MYSQL_LIBS="`$MYSQL_CONFIG --libs_r`"
		AC_MSG_RESULT($MYSQL_LIBS)
  	fi

	AC_SUBST(MYSQL_INCLUDES)
	AC_SUBST(MYSQL_LIBS)
])

AC_DEFUN([ACX_BOTAN],[
	AC_ARG_WITH(botan,
        	AC_HELP_STRING([--with-botan=DIR],[Location of the Botan crypto library]),
		[
			BOTAN_PATH="$withval"
		],
		[
			BOTAN_PATH="/usr/local"
		])

	AC_MSG_CHECKING(what are the Botan includes)
	BOTAN_INCLUDES="-I$BOTAN_PATH/include"
	AC_MSG_RESULT($BOTAN_INCLUDES)

	AC_MSG_CHECKING(what are the Botan libs)
	BOTAN_LIBS="-L$BOTAN_PATH/lib -lbotan"
	AC_MSG_RESULT($BOTAN_LIBS)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $BOTAN_INCLUDES"
	LIBS="$LIBS $BOTAN_LIBS"

	AC_LANG_PUSH([C++])
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM([#include <botan/init.h>
			#include <botan/pipe.h>
			#include <botan/filters.h>
			#include <botan/hex.h>
			#include <botan/sha2_32.h>
			#include <botan/auto_rng.h>
			#include <botan/emsa3.h>],
			[using namespace Botan;
			LibraryInitializer::initialize();
			new EMSA3_Raw();
			AutoSeeded_RNG *rng = new AutoSeeded_RNG();
			rng->reseed();])],
		[AC_MSG_RESULT([checking for Botan >= v1.7.24 and != v1.8.2 ... yes])],
		[AC_MSG_RESULT([checking for Botan >= v1.7.24 and != v1.8.2 ... no])
		 AC_MSG_ERROR([Missing the correct version of the Botan library])]
	)
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(BOTAN_INCLUDES)
	AC_SUBST(BOTAN_LIBS)
])

AC_DEFUN([ACX_DLOPEN],[
	AC_CHECK_FUNC(dlopen, [
			if test $ac_cv_func_dlopen = yes; then
			AC_DEFINE(HAVE_DLOPEN, 1, [Whether dlopen is available])
			fi
		], [
			AC_CHECK_FUNC(LoadLibrary, [
				if test $ac_cv_func_LoadLibrary = yes; then
					AC_DEFINE(HAVE_LOADLIBRARY, 1, [Whether LoadLibrary is available])
				fi
			], [
				AC_MSG_ERROR(No dynamic library loading support)
			])
		])
])

# routine to help check for compiler flags.
AC_DEFUN([CHECK_COMPILER_FLAG],[
	AC_REQUIRE([AC_PROG_CC])
	AC_MSG_CHECKING(whether $CC supports -$1)
	cache=`echo $1 | sed 'y% .=/+-%____p_%'`
	AC_CACHE_VAL(cv_prog_cc_flag_$cache,
	[
		echo 'void f(){}' >conftest.c
		if test -z "`$CC -$1 -c conftest.c 2>&1`"; then
			eval "cv_prog_cc_flag_$cache=yes"
		else
			eval "cv_prog_cc_flag_$cache=no"
		fi
		rm -f conftest*
	])
	if eval "test \"`echo '$cv_prog_cc_flag_'$cache`\" = yes"; then
		AC_MSG_RESULT(yes)
		:
		$2
	else
		AC_MSG_RESULT(no)
		:
		$3
	fi
])

# if the given code compiles without the flag, execute argument 4
# if the given code only compiles with the flag, execute argument 3
# otherwise fail
AC_DEFUN([CHECK_COMPILER_FLAG_NEEDED],[
	AC_REQUIRE([AC_PROG_CC])
	AC_MSG_CHECKING(whether we need $1 as a flag for $CC)
	cache=`echo $1 | sed 'y% .=/+-%____p_%'`
	AC_CACHE_VAL(cv_prog_cc_flag_needed_$cache,
	[
		echo '$2' > conftest.c
		echo 'void f(){}' >>conftest.c
		if test -z "`$CC $CFLAGS -Werror -Wall -c conftest.c 2>&1`"; then
			eval "cv_prog_cc_flag_needed_$cache=no"
		else
		[
			if test -z "`$CC $CFLAGS $1 -Werror -Wall -c conftest.c 2>&1`"; then
				eval "cv_prog_cc_flag_needed_$cache=yes"
			else
				echo 'Test with flag fails too'
			fi
		]
		fi
		rm -f conftest*
	])
	if eval "test \"`echo '$cv_prog_cc_flag_needed_'$cache`\" = yes"; then
		AC_MSG_RESULT(yes)
		:
		$3
	else
		AC_MSG_RESULT(no)
		:
		$4
	fi
])

AC_DEFUN([ACX_64BIT],[
	AC_ARG_ENABLE(
	        [64bit],
        	[AS_HELP_STRING([--enable-64bit],[enable 64-bit compiling])],
	        [enable_64bit="yes"],
	        [enable_64bit="no"])

	if test "x$enable_64bit" = "xyes"
	then
	        AC_MSG_CHECKING(if we can compile in 64-bit mode)
	        tmp_CFLAGS=$CFLAGS
	        CFLAGS="-m64"
	        AC_RUN_IFELSE(
	                [
				AC_LANG_PROGRAM([],[return sizeof(void*) == 8 ? 0 : 1;])
			], [
	                        AC_MSG_RESULT(yes)
	                        CXXFLAGS="-m64 $CXXFLAGS"
	                        LDFLAGS="-m64 $LDFLAGS"
	                        CFLAGS="-m64 $tmp_CFLAGS"
	                ],[
	                        AC_MSG_RESULT(no)
	                        AC_MSG_ERROR([Don't know how to compile in 64-bit mode.])
	                ]
	        )
	        CFLAGS=$tmp_CFLAGS
	fi

])
