# $Id$

lib_LTLIBRARIES = libsofthsm.la
libsofthsm_la_SOURCES = 	main.cpp \
				mutex.cpp \
				file.cpp \
				log.cpp \
				SoftHSMInternal.cpp \
				SoftSession.cpp \
				SoftObject.cpp \
				SoftFind.cpp \
				SoftAttribute.cpp \
				SoftDatabase.cpp \
				SoftKeyStore.cpp
libsofthsm_la_LDFLAGS =		-version-info @VERSION_INFO@
libsofthsm_la_CPPFLAGS = -I. -DSOFTLOGLEVEL=@SOFTLOGLEVEL@

EXTRA_DIST = *.h
