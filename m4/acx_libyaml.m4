AC_DEFUN([ACX_LIBYAML],[
	AC_CHECK_FUNC(
		[yaml_parser_initialize],
		[
			AC_DEFINE(HAVE_YAML, 1, [Define if you have libjannson])
		],
		[
			AC_CHECK_LIB(
				[yaml],
				[yaml_parser_initialize],
				[
					AC_DEFINE(HAVE_YAML, 1, [Define if you have libyaml])
					LIBS="$LIBS -lyaml"
				],
				[
					AC_MSG_ERROR([No libyaml found])
				]
			)
		]
	)
])
