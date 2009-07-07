# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = 		-I$(srcdir)/../lib \
			-I$(srcdir)/../lib/cryptoki \
			@BOTAN_INCLUDES@ \
			@SQLITE3_INCLUDES@

bin_PROGRAMS =		softhsm
softhsm_SOURCES =	softhsm.cpp softhsm.h
softhsm_LDADD =		../lib/libsofthsm.la -lstdc++ @BOTAN_LIBS@ @SQLITE3_LIBS@
softhsm_LDFLAGS =	-no-install

EXTRA_DIST =		$(srcdir)/*.h
