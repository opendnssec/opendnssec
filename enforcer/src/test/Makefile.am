MAINTAINERCLEANFILES = $(srcdir)/Makefile.in ${srcdir)/conf.xml $(srcdir)/setup. sh

LIBHSM = ${top_builddir}/libhsm/src/lib/libhsm.a
LIBCOMPAT = ${top_builddir}/common/libcompat.a

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_builddir)/common \
	-I$(top_srcdir) \
	-I$(top_srcdir)/common \
	-I$(srcdir)/.. \
	-I$(top_srcdir)/common \
	-I$(top_srcdir)/libhsm/src/lib \
	@PTHREAD_LIBS@ \
	@RT_LIBS@ \
	@CUNIT_INCLUDES@ \
	@XML2_INCLUDES@

check_PROGRAMS = enforcertest

EXTRA_DIST = opendnssec.conf

BACKEND_SOURCES_CUSTOM =
BACKEND_LDFLAGS_CUSTOM = -lm
BACKEND_SCHEMA_CUSTOM =

if USE_MYSQL
BACKEND_SOURCES_CUSTOM += db/db_backend_mysql.o
BACKEND_SCHEMA_CUSTOM += db/db_schema_mysql.o db/db_data_mysql.o
endif

if USE_SQLITE
BACKEND_SOURCES_CUSTOM += ../db/db_backend_sqlite.o
BACKEND_SCHEMA_CUSTOM += ../db/db_schema_sqlite.o ../db/db_data_sqlite.o
endif

enforcertest_SOURCES = enforcertest.c
enforcertest_LDFLAGS = -rdynamic
enforcertest_LDADD = \
	../daemon/cfg.o \
	../daemon/enforcercommands.o \
	../daemon/engine.o  \
	../daemon/help_cmd.o  \
	../daemon/time_leap_cmd.o  \
	../daemon/queue_cmd.o  \
	../daemon/verbosity_cmd.o  \
	../daemon/ctrl_cmd.o  \
	../parser/confparser.o  \
	../policy/policy_export_cmd.o  \
	../policy/policy_purge_cmd.o  \
	../policy/policy_export.o  \
	../policy/policy_import.o  \
	../policy/policy_import_cmd.o  \
	../policy/policy_list_cmd.o  \
	../policy/policy_resalt_cmd.o  \
	../policy/policy_resalt_task.o  \
	../hsmkey/backup_hsmkeys_cmd.o  \
	../hsmkey/hsm_key_factory.o  \
	../hsmkey/key_generate_cmd.o  \
	../keystate/zone_list_cmd.o  \
	../keystate/zone_add_cmd.o  \
	../keystate/zone_del_cmd.o  \
	../keystate/zone_set_policy_cmd.o  \
	../keystate/keystate_list_cmd.o  \
	../keystate/rollover_list_cmd.o  \
	../keystate/keystate_export_cmd.o  \
	../keystate/keystate_import_cmd.o  \
	../keystate/keystate_ds_submit_cmd.o  \
	../keystate/keystate_ds_submit_task.o  \
	../keystate/keystate_ds_seen_cmd.o  \
	../keystate/keystate_ds_retract_cmd.o  \
	../keystate/keystate_ds_retract_task.o  \
	../keystate/keystate_ds.o  \
	../keystate/keystate_ds_gone_cmd.o  \
	../keystate/keystate_rollover_cmd.o  \
	../keystate/key_purge_cmd.o  \
	../keystate/key_purge.o  \
	../keystate/zonelist_import.o  \
	../keystate/zonelist_import_cmd.o  \
	../keystate/zonelist_export.o  \
	../keystate/zonelist_export_cmd.o  \
	../keystate/zonelist_update.o  \
	../signconf/signconf_cmd.o  \
	../signconf/signconf_task.o  \
	../signconf/signconf_xml.o  \
	../enforcer/autostart_cmd.o  \
	../enforcer/enforce_cmd.o  \
	../enforcer/enforce_task.o  \
	../enforcer/enforcer.o  \
	../enforcer/update_repositorylist_cmd.o  \
	../enforcer/repositorylist_cmd.o  \
	../enforcer/update_all_cmd.o  \
	../enforcer/update_conf_cmd.o  \
	../utils/kc_helper.o  \
	../db/db_backend.o  \
	../db/db_clause.o  \
	../db/db_configuration.o  \
	../db/db_connection.o  \
	../db/db_object.o  \
	../db/db_result.o  \
	../db/db_type.h \
	../db/db_value.o  \
	../db/db_join.o  \
	../db/db_error.h \
	../db/zone_db.o \
	../db/zone_db_ext.o  \
	../db/key_data.o \
	../db/key_data_ext.o  \
	../db/key_state.o  \
	../db/key_dependency.o \
	../db/key_dependency_ext.o \
	../db/policy.o \
	../db/policy_ext.o \
	../db/policy_key.o \
	../db/policy_key_ext.o \
	../db/hsm_key.o \
	../db/hsm_key_ext.o \
	../db/database_version.o \
	../db/database_version_ext.o \
	$(BACKEND_SOURCES_CUSTOM) \
	$(LIBHSM) $(LIBCOMPAT) \
	@LDNS_LIBS@ @XML2_LIBS@ @PTHREAD_LIBS@ @RT_LIBS@ @SSL_LIBS@ @C_LIBS@ \
	@ENFORCER_DB_LIBS@ \
	@CUNIT_LIBS@

check: enforcertest conf.xml setup.sh
	sh setup.sh
	./enforcertest $(top_srcdir)/enforcer/src/test
