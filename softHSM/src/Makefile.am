# $Id$

lib_LTLIBRARIES = libsoftHSM.pkcs11.2.20.la
libsoftHSM_pkcs11_2_20_la_SOURCES = 	main.cpp \
					file.cpp \
					SoftHSMInternal.cpp \
					SoftSession.cpp \
					SoftObject.cpp \
					SoftFind.cpp \
					SoftAttribute.cpp
libsoftHSM_pkcs11_2_20_la_LDFLAGS = -L/usr/local/lib -lbotan -version-info 1:0:0
libsoftHSM_pkcs11_2_20_la_CPPFLAGS = -I. -I/usr/local/include
