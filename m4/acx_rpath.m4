# $Id$

dnl Add option to disable the evil rpath. Check whether to use rpath or not.
dnl Adds the --disable-rpath option. Uses trick to edit the ./libtool.
AC_DEFUN([ACX_ARG_RPATH],
[
	AC_ARG_ENABLE(rpath,
		[AS_HELP_STRING([--disable-rpath],
			[disable hardcoded rpath (default=enabled)])],
		[enable_rpath=$enableval],
		[enable_rpath=yes])

	if test "x$enable_rpath" = xno; then
		AC_MSG_RESULT([Fixing libtool for -rpath problems.])
		sed < libtool > libtool-2 \
		's/^hardcode_libdir_flag_spec.*$'/'hardcode_libdir_flag_spec=" -D__LIBTOOL_RPATH_SED__ "/'
		mv libtool-2 libtool
		chmod 755 libtool
		libtool="./libtool"
	fi
])

dnl Add a -R to the RUNTIME_PATH.  Only if rpath is enabled and it is
dnl an absolute path.
dnl $1: the pathname to add.
AC_DEFUN([ACX_RUNTIME_PATH_ADD], [
	if test "x$enable_rpath" = xyes; then
		if echo "$1" | grep "^/" >/dev/null; then
			RUNTIME_PATH="$RUNTIME_PATH -R$1"
		fi
	fi
])
