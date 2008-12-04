# $Id$

lib_LTLIBRARIES = libsofthsm.la
libsofthsm_la_SOURCES = 	main.cpp \
				mutex.cpp \
				file.cpp \
				SoftHSMInternal.cpp \
				SoftSession.cpp \
				SoftObject.cpp \
				SoftFind.cpp \
				SoftAttribute.cpp
libsofthsm_la_LDFLAGS = -L@BOTANDIR@ -R@BOTANDIR@ -lbotan -version-info @VERSION_INFO@
libsofthsm_la_CPPFLAGS = -I. -I/usr/local/include
