# $Id: Makefile.am 4952 2011-03-29 09:05:41Z rb $

MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/.. \
				-I$(srcdir)/../.. \
				`cppunit-config --cflags`

check_PROGRAMS =		pbormtest

pbormtest_SOURCES =		pbormtest.cc \
							pb-orm-zone-tests.cc \
							pb-orm-common.cc \
							pb-orm-value.cc \
							pb-orm-error.cc \
							pb-orm-transaction.cc \
							pb-orm-create-table.cc \
							pb-orm-drop-table.cc \
							pb-orm-enum.cc \
							pb-orm-create.cc \
							pb-orm-read.cc \
							pb-orm-update.cc \
							pb-orm-delete.cc

pbormtest_LDADD =		

pbormtest_LDFLAGS = 		-no-install `cppunit-config --libs`

TESTS = 			pbormtest

EXTRA_DIST =			$(srcdir)/*.h
