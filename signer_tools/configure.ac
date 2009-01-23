
AC_INIT(pipeline_signer, 0.1, jelte@NLnetLabs.nl)

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
AC_CHECK_FUNC(ldns_key_external_key, [], [
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

AC_CONFIG_HEADERS([config.h])
AC_OUTPUT(Makefile)
