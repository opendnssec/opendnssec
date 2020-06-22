AC_DEFUN([ACX_PKCS11_MODULES],[
	AC_ARG_WITH(pkcs11-softhsm, 
		AS_HELP_STRING([--with-pkcs11-softhsm=PATH],[specify path of SoftHSM PKCS#11 library (default PREFIX/lib/softhsm/libsofthsm2.so)]),
		[ pkcs11_softhsm_module="$withval" ],
		[ pkcs11_softhsm_module="$full_libdir/softhsm/libsofthsm2.so" ]
	)
	
	AC_SUBST(pkcs11_softhsm_module)
])
