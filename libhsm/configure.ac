# $Id$

AC_PREREQ(2.61)
AC_INIT([libhsm],[0.0.3],[jelte@nlnetlabs.nl])

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

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
ACX_LDNS
ACX_DLOPEN

full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
AC_DEFINE_UNQUOTED([HSM_DEFAULT_CONFIG],["${full_sysconfdir}/opendnssec/conf.xml"],[Default configuration file.])

AC_ARG_WITH(pkcs11-softhsm, 
	AS_HELP_STRING([--with-pkcs11-softhsm=PATH],[specify path of SoftHSM library to use for regression testing (default PREFIX/lib/libsofthsm.so)]),
	[ pkcs11_softhsm_module="$withval" ],
	[ pkcs11_softhsm_module="$prefix/lib/libsofthsm.so" ]
)

AC_ARG_WITH(pkcs11-sca6000, 
	AS_HELP_STRING([--with-pkcs11-sca6000=PATH],[specify path of SCA6000 library to use for regression testing (default /usr/lib/libpkcs11.so)]),
	[ pkcs11_sca6000_module="$withval" ],
	[ pkcs11_sca6000_module="/usr/lib/libpkcs11.so" ]
)

AC_ARG_WITH(pkcs11-etoken, 
	AS_HELP_STRING([--with-pkcs11-etoken=PATH],[specify path of Aladdin eToken library to use for regression testing (default /usr/local/lib/libeTPkcs11.so)]),
	[ pkcs11_etoken_module="$withval" ],
	[ pkcs11_etoken_module="/usr/local/lib/libeTPkcs11.so" ]
)

AC_ARG_WITH(pkcs11-opensc, 
	AS_HELP_STRING([--with-pkcs11-opensc=PATH],[specify path of Aladdin eToken library to use for regression testing (default /usr/lib/pkcs11/opensc-pkcs11.so)]),
	[ pkcs11_opensc_module="$withval" ],
	[ pkcs11_opensc_module="/usr/lib/pkcs11/opensc-pkcs11.so" ]
)

AC_SUBST(pkcs11_softhsm_module)
AC_SUBST(pkcs11_sca6000_module)
AC_SUBST(pkcs11_etoken_module)
AC_SUBST(pkcs11_opensc_module)

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	checks/Makefile
	checks/conf-softhsm.xml
	checks/conf-sca6000.xml
	checks/conf-etoken.xml
	checks/conf-multi.xml
	checks/conf-opensc.xml
])

AC_OUTPUT
