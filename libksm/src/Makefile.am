# $Id$

AM_CFLAGS = -pedantic -Wall -I../include @DB_INCLUDES@
lib_LTLIBRARIES = libksm.la
if MYSQL
libksm_la_SOURCES = database_access.c database_connection.c database_init_rundown.c database_support.c datetime.c dd_string.c debug.c di_string.c dq_string.c du_string.c ksm_dnsseckeys.c ksm_init_rundown.c ksm_key.c ksm_key_delete.c ksm_keyword.c ksm_parameter.c ksm_parameter_value.c ksm_policy.c ksm_policy_value.c ksm_purge.c ksm_request.c ksm_time.c ksm_update.c ksm_version.c ksm_zone.c memory.c message.c string_util.c string_util2.c strlcpy.c strlcat.c
else
libksm_la_SOURCES = database_access_lite.c database_connection_lite.c database_init_rundown.c database_support_lite.c datetime.c dd_string.c debug.c di_string.c dq_string.c du_string.c ksm_dnsseckeys.c ksm_init_rundown.c ksm_key.c ksm_key_delete.c ksm_keyword.c ksm_parameter.c ksm_parameter_value.c ksm_policy.c ksm_policy_value.c ksm_purge.c ksm_request.c ksm_time.c ksm_update.c ksm_version.c ksm_zone.c memory.c message.c string_util.c string_util2.c strlcpy.c strlcat.c
endif
libksm_la_LDFLAGS = @DB_LIBS@
