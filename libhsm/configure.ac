#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([libhsm],[0.0.1],[jelte@nlnetlabs.nl])
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
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

opendnssecsysconfdir="$sysconfdir/opendnssec"
AC_DEFINE_UNQUOTED([HSM_DEFAULT_CONFIG],["$opendnssecsysconfdir/conf.xml"],[Default configuration file.])

AC_ARG_WITH(pkcs11-softhsm, 
	AC_HELP_STRING([--with-pkcs11-softhsm=PATH],[specify path of SoftHSM library to use for regression testing (default PREFIX/lib/libsofthsm.so)]),
	[ pkcs11_softhsm_module="$withval" ],
	[ pkcs11_softhsm_module="$prefix/lib/libsofthsm.so" ]
)

AC_ARG_WITH(pkcs11-sca6000, 
	AC_HELP_STRING([--with-pkcs11-sca6000=PATH],[specify path of SCA6000 library to use for regression testing (default /usr/lib/libpkcs11.so)]),
	[ pkcs11_sca6000_module="$withval" ],
	[ pkcs11_sca6000_module="/usr/lib/libpkcs11.so" ]
)

AC_ARG_WITH(pkcs11-etoken, 
	AC_HELP_STRING([--with-pkcs11-etoken=PATH],[specify path of Aladdin eToken library to use for regression testing (default /usr/local/lib/libeTPkcs11.so)]),
	[ pkcs11_etoken_module="$withval" ],
	[ pkcs11_etoken_module="/usr/local/lib/libeTPkcs11.so" ]
)

AC_SUBST(pkcs11_softhsm_module)
AC_SUBST(pkcs11_sca6000_module)
AC_SUBST(pkcs11_etoken_module)

AC_CONFIG_FILES([
Makefile
src/Makefile
checks/Makefile
])

AC_OUTPUT([
checks/conf-softhsm.xml
checks/conf-sca6000.xml
checks/conf-etoken.xml
checks/conf-multi.xml
])
