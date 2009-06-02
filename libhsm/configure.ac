#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([libhsm],[0.0.1],[jelte@nlnetlabs.nl])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/libhsm.c])
AC_CONFIG_HEADER([config.h])

AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

ACX_PEDANTIC
ACX_STRICT
 
# Checks for libraries.
AC_CHECK_LIB([dl], [dlopen])
AC_CHECK_LIB([uuid], [uuid_generate])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([getpass getpassphrase memset])

ACX_LIBXML2
ACX_LDNS
ACX_DLOPEN

AC_ARG_WITH(softhsm, 
	AC_HELP_STRING([--with-softhsm=PATH],[specify path of SoftHSM library to use for regression testing (default PREFIX/lib/libsofthsm.so)]),
	[
		softhsm_module="$withval"
	],
	[
		softhsm_module=$prefix/lib/libsofthsm.so
	]
)

AC_ARG_WITH(sca6000, 
	AC_HELP_STRING([--with-sca6000=PATH],[specify path of SCA6000 library to use for regression testing (default /usr/lib/libpkcs11.so)]),
	[
		sca6000_module="$withval"
	],
	[
		sca6000_module=/usr/lib/libpkcs11.so
	]
)

AC_SUBST(softhsm_module)
AC_SUBST(sca6000_module)

AC_CONFIG_FILES([
Makefile
src/Makefile
checks/Makefile
])

AC_OUTPUT([
checks/conf-softhsm.xml
checks/conf-sca6000.xml
])
