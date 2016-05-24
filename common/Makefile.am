MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	@LDNS_INCLUDES@

noinst_LIBRARIES = libcompat.a
noinst_PROGRAMS = crashtest

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
	datastructure.c datastructure.h \
	janitor.c janitor.h
crashtest_SOURCES = janitor.c crashtest.c
crashtest_CFLAGS = -fno-inline-functions -fno-inline -fno-default-inline -fno-inline-functions-called-once -fkeep-inline-functions -O0
crashtest_LDFLAGS = -fno-inline-functions -fno-inline -fvisibility-inlines-hidden -fno-default-inline -fno-inline-functions-called-once -fkeep-inline-functions -O0
