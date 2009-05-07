# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

lib_LTLIBRARIES =		libsofthsm.la
libsofthsm_la_SOURCES =		main.cpp \
				mutex.cpp \
				file.cpp \
				log.cpp \
				userhandling.cpp \
				SoftHSMInternal.cpp \
				SoftSlot.cpp \
				SoftSession.cpp \
				SoftFind.cpp \
				SoftAttribute.cpp \
				SoftDatabase.cpp \
				SoftKeyStore.cpp
libsofthsm_la_LDFLAGS =		-version-info @VERSION_INFO@
libsofthsm_la_CPPFLAGS =	-I.

EXTRA_DIST =			*.h
