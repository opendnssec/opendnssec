AC_DEFUN([ACX_LIBMICROHTTPD],[
	AC_CHECK_FUNC(
		[MHD_start_daemon],
		[
			AC_DEFINE(HAVE_MICROHTTPD, 1, [Define if you have MHD_start_daemon])
		],
		[
			AC_CHECK_LIB(
				[microhttpd],
				[MHD_start_daemon],
				[
					AC_DEFINE(HAVE_MICROHTTPD, 1, [Define if you have MHD_start_daemon])
					LIBS="$LIBS -lmicrohttpd"
				],
				[
					AC_MSG_ERROR([No libmicrohttpd found])
				]
			)
		]
	)
])
