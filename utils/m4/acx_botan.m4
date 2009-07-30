# $Id$

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
			#include <botan/emsa3.h>],
			[using namespace Botan;
			LibraryInitializer::initialize();
			new EMSA3_Raw();])],
		[AC_MSG_RESULT([checking for Botan >= v1.8.0 ... yes])],
		[AC_MSG_RESULT([checking for Botan >= v1.8.0 ... no])
		 AC_MSG_ERROR([Missing the correct version of the Botan library])]
	)
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
		[AC_MSG_RESULT([checking for Botan reseed API fix ... no])],
		[AC_MSG_RESULT([checking for Botan reseed API fix ... yes])
		AC_DEFINE_UNQUOTED(
			[BOTAN_RESEED_FIX],
			[1],
			[Fixes an API problem within Botan]
		)]
	)
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS

	AC_SUBST(BOTAN_INCLUDES)
	AC_SUBST(BOTAN_LIBS)
])
