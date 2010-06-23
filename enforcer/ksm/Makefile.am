# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SUBDIRS = include

AM_CPPFLAGS = \
	-I$(top_builddir)/common \
	-I$(srcdir)/include \
	-I$(builddir)/include \
	@DB_INCLUDES@ \
	@XML2_INCLUDES@

noinst_LIBRARIES = libksm.a

libksm_a_SOURCES = \
	database_init_rundown.c datetime.c dd_string.c debug.c di_string.c \
	dq_string.c du_string.c ksm_dnsseckeys.c ksm_import.c ksm_init_rundown.c \
	ksm_key.c ksm_key_delete.c ksm_keyword.c ksm_list.c ksm_parameter.c \
	ksm_parameter_value.c ksm_policy.c ksm_policy_value.c ksm_purge.c \
	ksm_request.c ksm_time.c ksm_update.c ksm_version.c ksm_zone.c \
	memory.c message.c string_util.c string_util2.c \
	compat/strlcpy.c compat/strlcat.c

if USE_MYSQL
libksm_a_SOURCES += \
	database_access_mysql.c \
	database_connection_mysql.c \
	database_support_mysql.c
else
libksm_a_SOURCES += \
	database_access_lite.c \
	database_connection_lite.c \
	database_support_lite.c
endif
