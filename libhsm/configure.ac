# $Id$

m4_sinclude([version.m4])

AC_PREREQ(2.61)
AC_INIT([opendnssec-libhsm], OPENDNSSEC_VERSION)

# code change; revision++
# API add, remove, changed; current++, revision=0
# API add; age++
# API remove; age=0
define([LIBHSM_SHLIB_CURRENT],  [2])
define([LIBHSM_SHLIB_REVISION], [0])
define([LIBHSM_SHLIB_AGE],      [2])

# needed to build correct soname
AC_SUBST(LIBTOOL_VERSION_INFO, "LIBHSM_SHLIB_CURRENT:LIBHSM_SHLIB_REVISION:LIBHSM_SHLIB_AGE")

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

OPENDNSSEC_COMMON

AC_CONFIG_SRCDIR([src/libhsm.c])
AC_CONFIG_HEADER([config.h])

AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

ACX_ARG_RPATH
ACX_RUNTIME_PATH_ADD

ACX_PEDANTIC
ACX_STRICT
 
# Checks for libraries.
#AC_CHECK_LIB([dl], [dlopen])

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
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([getpass getpassphrase memset])
AC_REPLACE_FUNCS(strlcpy)
AC_REPLACE_FUNCS(strlcat)

ACX_LIBXML2
ACX_LDNS(1,6,4)
ACX_DLOPEN

AC_DEFINE_UNQUOTED([HSM_DEFAULT_CONFIG],["$OPENDNSSEC_CONFIG_FILE"],[Default configuration file.])

ACX_PKCS11_MODULES

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/ods-hsmspeed.1
	src/ods-hsmutil.1
	checks/Makefile
	checks/conf-softhsm.xml
	checks/conf-sca6000.xml
	checks/conf-etoken.xml
	checks/conf-multi.xml
	checks/conf-opensc.xml
	checks/conf-ncipher.xml
	checks/conf-aepkeyper.xml
])

AC_OUTPUT
