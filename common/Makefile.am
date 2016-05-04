MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	@LDNS_INCLUDES@

noinst_LIBRARIES = libcompat.a
noinst_PROGRAMS = debugtest

libcompat_a_SOURCES = \
	b64_ntop.c b64_pton.c \
	clientpipe.c clientpipe.h \
	compat.h \
	duration.c duration.h \
	file.c file.h \
	locks.c locks.h \
	log.c log.h \
	privdrop.c privdrop.h \
	pselect.c \
	status.c status.h \
	str.c str.h strlcat.c strlcpy.c \
	util.c util.h \
	datastructure.c datastructure.h
debugtest_SOURCES = debug.c debugtest.c
debugtest_CFLAGS = -fno-inline-small-functions -fno-inline-functions