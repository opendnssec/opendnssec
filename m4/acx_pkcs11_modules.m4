AC_DEFUN([ACX_PKCS11_MODULES],[
	AC_ARG_WITH(pkcs11-softhsm, 
		AS_HELP_STRING([--with-pkcs11-softhsm=PATH],[specify path of SoftHSM PKCS#11 library (default PREFIX/lib/softhsm/libsofthsm2.so)]),
		[ pkcs11_softhsm_module="$withval" ],
		[ pkcs11_softhsm_module="$full_libdir/softhsm/libsofthsm2.so" ]
	)
	
	AC_ARG_WITH(pkcs11-sca6000, 
		AS_HELP_STRING([--with-pkcs11-sca6000=PATH],[specify path of SCA/6000 PKCS#11 library (default /usr/lib/libpkcs11.so)]),
		[ pkcs11_sca6000_module="$withval" ],
		[ pkcs11_sca6000_module="/usr/lib/libpkcs11.so" ]
	)
	
	AC_ARG_WITH(pkcs11-etoken, 
		AS_HELP_STRING([--with-pkcs11-etoken=PATH],[specify path of Aladdin eToken PKCS#11 library (default /usr/local/lib/libeTPkcs11.so)]),
		[ pkcs11_etoken_module="$withval" ],
		[ pkcs11_etoken_module="/usr/local/lib/libeTPkcs11.so" ]
	)
	
	AC_ARG_WITH(pkcs11-opensc, 
		AS_HELP_STRING([--with-pkcs11-opensc=PATH],[specify path of OpenSC PKCS#11 library (default /usr/lib/pkcs11/opensc-pkcs11.so)]),
		[ pkcs11_opensc_module="$withval" ],
		[ pkcs11_opensc_module="/usr/lib/pkcs11/opensc-pkcs11.so" ]
	)
	
	AC_ARG_WITH(pkcs11-ncipher, 
		AS_HELP_STRING([--with-pkcs11-ncipher=PATH],[specify path of nCipher PKCS#11 library (default /opt/nfast/toolkits/pkcs11/libcknfast.so)]),
		[ pkcs11_ncipher_module="$withval" ],
		[ pkcs11_ncipher_module="/opt/nfast/toolkits/pkcs11/libcknfast.so" ]
	)
	
	AC_ARG_WITH(pkcs11-aepkeyper, 
		AS_HELP_STRING([--with-pkcs11-aepkeyper=PATH],[specify path of AEP Keyper PKCS#11 library (default /opt/Keyper/PKCS11Provider/pkcs11.so)]),
		[ pkcs11_aepkeyper_module="$withval" ],
		[ pkcs11_aepkeyper_module="/opt/Keyper/PKCS11Provider/pkcs11.so" ]
	)
	
	AC_SUBST(pkcs11_softhsm_module)
	AC_SUBST(pkcs11_sca6000_module)
	AC_SUBST(pkcs11_etoken_module)
	AC_SUBST(pkcs11_opensc_module)
	AC_SUBST(pkcs11_ncipher_module)
	AC_SUBST(pkcs11_aepkeyper_module)
])
