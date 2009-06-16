# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = 		-I$(srcdir) \
			-I$(srcdir)/../lib \
			-I$(srcdir)/../lib/cryptoki \
			$(SQLITE3_INCLUDES)

bin_PROGRAMS =		softhsm
softhsm_SOURCES =	softhsm.cpp softhsm.h
softhsm_LDADD =		../lib/libsofthsm.la -lstdc++
softhsm_LDFLAGS =	-no-install $(SQLITE3_LIBS)

EXTRA_DIST =		$(srcdir)/*.h
