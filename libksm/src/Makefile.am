# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SUBDIRS = include

AM_CPPFLAGS = \
	-I$(srcdir)/include \
	-Iinclude \
	 @LIBHSM_INCLUDES@ \
	 @DB_INCLUDES@ \
     @XML2_INCLUDES@

libksm_la_LIBADD = @DB_LIBS@ @LIBHSM_LIBS@

libksm_la_SOURCES = \
	database_init_rundown.c datetime.c dd_string.c debug.c di_string.c \
	dq_string.c du_string.c ksm_dnsseckeys.c ksm_import.c ksm_init_rundown.c \
	ksm_key.c ksm_key_delete.c ksm_keyword.c ksm_parameter.c \
	ksm_parameter_value.c ksm_policy.c ksm_policy_value.c ksm_purge.c \
	ksm_request.c ksm_time.c ksm_update.c ksm_version.c ksm_zone.c \
	memory.c message.c string_util.c string_util2.c \
	compat/strlcpy.c compat/strlcat.c

if MYSQL
libksm_la_SOURCES += \
	database_access_mysql.c \
	database_connection_mysql.c \
	database_support_mysql.c 
else
libksm_la_SOURCES += \
	database_access_lite.c \
	database_connection_lite.c \
	database_support_lite.c
endif

bin_PROGRAMS = ksmutil
ksmutil_LDADD = libksm.la @XML2_LIBS@

lib_LTLIBRARIES = libksm.la
