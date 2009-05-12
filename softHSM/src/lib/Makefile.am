# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS =			-I$(srcdir) -I$(srcdir)/cryptoki \
				-DSOFT_CONFIG_FILE='"$(sysconfdir)/softhsm.conf"'

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

EXTRA_DIST =			$(srcdir)/*.h \
				$(srcdir)/cryptoki/*.h
