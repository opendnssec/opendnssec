# $Id$

AC_DEFUN([ACX_PKCS11_MODULES],[
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
	
	AC_ARG_WITH(pkcs11-opensc, 
		AC_HELP_STRING([--with-pkcs11-opensc=PATH],[specify path of Aladdin eToken library to use for regression testing (default /usr/lib/pkcs11/opensc-pkcs11.so)]),
		[ pkcs11_opensc_module="$withval" ],
		[ pkcs11_opensc_module="/usr/lib/pkcs11/opensc-pkcs11.so" ]
	)
	
	AC_SUBST(pkcs11_softhsm_module)
	AC_SUBST(pkcs11_sca6000_module)
	AC_SUBST(pkcs11_etoken_module)
	AC_SUBST(pkcs11_opensc_module)
])
