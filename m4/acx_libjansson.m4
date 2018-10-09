AC_DEFUN([ACX_LIBJANSSON],[
	AC_CHECK_FUNC(
		[json_loads],
		[
			AC_DEFINE(HAVE_JANSSON, 1, [Define if you have libjannson])
		],
		[
			AC_CHECK_LIB(
				[jansson],
				[json_loads],
				[
					AC_DEFINE(HAVE_JANSSON, 1, [Define if you have libjannson])
					LIBS="$LIBS -ljansson"
				],
				[
					AC_MSG_ERROR([No libjanson found])
				]
			)
		]
	)
])
