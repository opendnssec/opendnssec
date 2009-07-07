# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS =			-I$(srcdir)/cryptoki \
				@BOTAN_INCLUDES@ \
				@SQLITE3_INCLUDES@

lib_LTLIBRARIES =		libsofthsm.la
libsofthsm_la_SOURCES =		main.cpp \
				mutex.cpp \
				file.cpp \
				log.cpp \
				attribute.cpp \
				userhandling.cpp \
				tokenhandling.cpp \
				mechanisms.cpp \
				SoftHSMInternal.cpp \
				SoftSlot.cpp \
				SoftSession.cpp \
				SoftFind.cpp \
				SoftDatabase.cpp \
				SoftKeyStore.cpp
libsofthsm_la_LIBADD =		@BOTAN_LIBS@ @SQLITE3_LIBS@
libsofthsm_la_LDFLAGS =		-version-info @VERSION_INFO@

EXTRA_DIST =			$(srcdir)/*.h \
				$(srcdir)/cryptoki/*.h
