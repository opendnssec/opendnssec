# $Id$

lib_LTLIBRARIES = libsofthsm.la libsofthsm.d.la
libsofthsm_la_SOURCES = 	main.cpp \
				mutex.cpp \
				file.cpp \
				SoftHSMInternal.cpp \
				SoftSession.cpp \
				SoftObject.cpp \
				SoftFind.cpp \
				SoftAttribute.cpp \
				SoftDatabase.cpp \
				SoftKeyStore.cpp
libsofthsm_la_LDFLAGS =		-version-info @VERSION_INFO@
libsofthsm_la_CPPFLAGS = -I.

libsofthsm_d_la_SOURCES =         main.cpp \
                                  mutex.cpp \
                                  file.cpp \
                                  SoftHSMInternal.cpp \
                                  SoftSession.cpp \
                                  SoftObject.cpp \
                                  SoftFind.cpp \
                                  SoftAttribute.cpp \
                                  SoftDatabase.cpp \
                                  SoftKeyStore.cpp
libsofthsm_d_la_LDFLAGS =         -version-info @VERSION_INFO@
libsofthsm_d_la_CPPFLAGS = -I. -DSOFTDEBUG

EXTRA_DIST = *.h
