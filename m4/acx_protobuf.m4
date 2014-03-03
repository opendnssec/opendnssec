AC_DEFUN([ACX_PROTOBUF],[
	AC_ARG_WITH(protobuf,
		[AC_HELP_STRING([--with-protobuf=PATH],[specify prefix of path of protobuf library to use])],
		[
			PROTOBUF_PATH="$withval"
		],[
			PROTOBUF_PATH="/usr/local"
		]
	)

	AC_MSG_CHECKING(what are the protobuf includes)
	PROTOBUF_INCLUDES="-I$PROTOBUF_PATH/include -I/usr/include"
	AC_MSG_RESULT($PROTOBUF_INCLUDES)

	AC_MSG_CHECKING(what are the protobuf libs)
	PROTOBUF_LIBS="-L$PROTOBUF_PATH/lib -lprotobuf"
	AC_MSG_RESULT($PROTOBUF_LIBS)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $PROTOBUF_INCLUDES"
	LIBS="$LIBS $PROTOBUF_LIBS"

	AC_LANG_PUSH([C++])

	AC_MSG_CHECKING([for protobuf])
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM([#include <google/protobuf/stubs/common.h>],
			[using namespace google::protobuf;
			DoNothing();])],
		[AC_MSG_RESULT([yes])],
		[AC_MSG_RESULT([no])
		 AC_MSG_ERROR([Missing the protobuf library])]
	)
	LIBS=$tmp_LIBS

	AC_MSG_CHECKING([for protobuf version])
	CHECK_PROTOBUF_VERSION=m4_eval($1 * 1000000 + $2 * 1000 + $3)
	AC_RUN_IFELSE([
		AC_LANG_SOURCE([[
			#include <google/protobuf/stubs/common.h>
			int main()
			{
			/* The current version, represented as a single integer to make comparison */
			/* easier:  major * 10^6 + minor * 10^3 + micro */
			#ifdef GOOGLE_PROTOBUF_VERSION
				if (GOOGLE_PROTOBUF_VERSION >= $CHECK_PROTOBUF_VERSION)
					return 0;
			#endif
				return 1;
			}
		]])
	],[
		AC_MSG_RESULT([>= $1.$2.$3])
	],[
		AC_MSG_RESULT([< $1.$2.$3])
		AC_MSG_ERROR([protobuf library too old ($1.$2.$3 or later required)])
	],[])

	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS

	AC_PATH_PROG(PROTOC, protoc)
	if test -z "$PROTOC"; then
		AC_MSG_ERROR([protoc not found])
	fi

	AC_SUBST(PROTOBUF_INCLUDES)
	AC_SUBST(PROTOBUF_LIBS)
])
