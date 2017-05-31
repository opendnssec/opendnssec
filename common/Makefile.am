MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	@LDNS_INCLUDES@ @XML2_INCLUDES@


noinst_LIBRARIES = libcompat.a

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
	scheduler/schedule.c scheduler/schedule.h \
	scheduler/task.c scheduler/task.h \
	scheduler/fifoq.c scheduler/fifoq.h \
	scheduler/worker.c scheduler/worker.h \
	scheduler/task.c scheduler/task.h \
	cmdhandler.c cmdhandler.h \
	presentation.c presentation.h \
	janitor.c janitor.h \
	cfg.c cfg.h \
	confparser.c confparser.h
