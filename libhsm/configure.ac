# $Id$

m4_sinclude([../version.m4])

AC_PREREQ(2.61)
AC_INIT([opendnssec-libhsm], OPENDNSSEC_VERSION)

# code change; revision++
# API add, remove, changed; current++, revision=0
# API add; age++
# API remove; age=0
define([LIBHSM_SHLIB_CURRENT],  [1])
define([LIBHSM_SHLIB_REVISION], [1])
define([LIBHSM_SHLIB_AGE],      [1])

# needed to build correct soname
AC_SUBST(LIBTOOL_VERSION_INFO, "LIBHSM_SHLIB_CURRENT:LIBHSM_SHLIB_REVISION:LIBHSM_SHLIB_AGE")

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

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

AC_ARG_WITH(pkcs11-ncipher, 
	AS_HELP_STRING([--with-pkcs11-ncipher=PATH],[specify path of nCiper library to use for regression testing (default /opt/nfast/toolkits/pkcs11/libcknfast.so)]),
	[ pkcs11_ncipher_module="$withval" ],
	[ pkcs11_ncipher_module="/opt/nfast/toolkits/pkcs11/libcknfast.so" ]
)

AC_ARG_WITH(pkcs11-aepkeyper, 
	AS_HELP_STRING([--with-pkcs11-aepkeyper=PATH],[specify path of AEP Keyper library to use for regression testing (default /opt/Keyper/PKCS11Provider/pkcs11.so)]),
	[ pkcs11_aepkeyper_module="$withval" ],
	[ pkcs11_aepkeyper_module="/opt/Keyper/PKCS11Provider/pkcs11.so" ]
)

AC_SUBST(pkcs11_softhsm_module)
AC_SUBST(pkcs11_sca6000_module)
AC_SUBST(pkcs11_etoken_module)
AC_SUBST(pkcs11_opensc_module)
AC_SUBST(pkcs11_aepkeyper_module)
AC_SUBST(pkcs11_ncipher_module)

AC_CONFIG_FILES([
	Makefile
	src/Makefile
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
