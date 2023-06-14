MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

EXTRA_DIST = 

CLEANFILES = $(BUILT_SOURCES)

LIBHSM = ${top_builddir}/libhsm/src/lib/libhsm.a
LIBCOMPAT = ${top_builddir}/common/libcompat.a

SUBDIRS = db/test

AM_CFLAGS = \
	-I$(top_srcdir)/common \
	-I$(top_builddir)/common \
	-I$(srcdir)/../../libhsm/src/lib \
	-I$(builddir)/../../libhsm/src/lib \
	@XML2_INCLUDES@ \
	@LDNS_INCLUDES@ \
	@ENFORCER_DB_INCLUDES@

enforcerdir =	@libdir@/opendnssec/enforcer

bin_PROGRAMS = ods-kaspcheck
sbin_PROGRAMS =	ods-enforcerd ods-enforcer ods-enforcer-db-setup ods-migrate
#dist_man1_MANS = utils/ods-kaspcheck.1

BACKEND_SOURCES_CUSTOM =
BACKEND_LDFLAGS_CUSTOM = -lm
BACKEND_SCHEMA_CUSTOM =

if USE_SQLITE
BACKEND_SOURCES_CUSTOM += db/db_backend_sqlite.c db/db_backend_sqlite.h
BACKEND_SCHEMA_CUSTOM += db/db_schema_sqlite.c db/db_schema_sqlite.h \
	db/db_data_sqlite.c db/db_data_sqlite.h db/schema.sqlite
endif

if USE_MYSQL
BACKEND_SOURCES_CUSTOM += db/db_backend_mysql.c db/db_backend_mysql.h
BACKEND_SCHEMA_CUSTOM += db/db_schema_mysql.c db/db_schema_mysql.h \
	db/db_data_mysql.c db/db_data_mysql.h db/schema.mysql
endif

ods_enforcerd_SOURCES = \
	ods-enforcerd.c \
	daemon/cfg.c daemon/cfg.h \
	daemon/enforcercommands.c daemon/enforcercommands.h \
	daemon/engine.c daemon/engine.h \
	daemon/time_leap_cmd.c daemon/time_leap_cmd.h \
	daemon/queue_cmd.c daemon/queue_cmd.h \
	daemon/verbosity_cmd.c daemon/verbosity_cmd.h \
	daemon/ctrl_cmd.c daemon/ctrl_cmd.h \
	parser/confparser.c parser/confparser.h \
	policy/policy_export_cmd.c policy/policy_export_cmd.h \
	policy/policy_purge_cmd.c policy/policy_purge_cmd.h \
	policy/policy_export.c policy/policy_export.h \
	policy/policy_import.c policy/policy_import.h \
	policy/policy_import_cmd.c policy/policy_import_cmd.h \
	policy/policy_list_cmd.c policy/policy_list_cmd.h \
	policy/policy_resalt_cmd.c policy/policy_resalt_cmd.h \
	policy/policy_resalt_task.c policy/policy_resalt_task.h \
	hsmkey/backup_hsmkeys_cmd.c hsmkey/backup_hsmkeys_cmd.h \
	hsmkey/hsm_key_factory.c hsmkey/hsm_key_factory.h \
	hsmkey/key_generate_cmd.c hsmkey/key_generate_cmd.h \
	keystate/zone_list_cmd.c keystate/zone_list_cmd.h \
	keystate/zone_add_cmd.c keystate/zone_add_cmd.h \
	keystate/zone_del_cmd.c keystate/zone_del_cmd.h \
	keystate/zone_set_policy_cmd.c keystate/zone_set_policy_cmd.h \
	keystate/keystate_list_cmd.c keystate/keystate_list_cmd.h \
	keystate/rollover_list_cmd.c keystate/rollover_list_cmd.h \
	keystate/keystate_export_cmd.c keystate/keystate_export_cmd.h \
	keystate/keystate_import_cmd.c keystate/keystate_import_cmd.h \
	keystate/keystate_ds_submit_cmd.c keystate/keystate_ds_submit_cmd.h \
	keystate/keystate_ds_submit_task.c keystate/keystate_ds_submit_cmd.h \
	keystate/keystate_ds_seen_cmd.c keystate/keystate_ds_seen_cmd.h \
	keystate/keystate_ds_retract_cmd.c keystate/keystate_ds_retract_cmd.h \
	keystate/keystate_ds_retract_task.c keystate/keystate_ds_retract_task.h \
	keystate/keystate_ds.c keystate/keystate_ds.h \
	keystate/keystate_ds_gone_cmd.c keystate/keystate_ds_gone_cmd.h \
	keystate/keystate_rollover_cmd.c keystate/keystate_rollover_cmd.h \
	keystate/key_purge_cmd.c keystate/key_purge_cmd.h \
	keystate/key_purge.c keystate/key_purge.h \
	keystate/zonelist_import.c keystate/zonelist_import.h \
	keystate/zonelist_import_cmd.c keystate/zonelist_import_cmd.h \
	keystate/zonelist_export.c keystate/zonelist_export.h \
	keystate/zonelist_export_cmd.c keystate/zonelist_export_cmd.h \
	keystate/zonelist_update.c keystate/zonelist_update.h \
	keystate/keystate_ds_submit_task.h \
	signconf/signconf_cmd.c signconf/signconf_cmd.h \
	signconf/signconf_task.c signconf/signconf_task.h \
	signconf/signconf_xml.c signconf/signconf_xml.h \
	enforcer/autostart_cmd.c enforcer/autostart_cmd.h \
	enforcer/enforce_cmd.c enforcer/enforce_cmd.h \
	enforcer/enforce_task.c enforcer/enforce_task.h \
	enforcer/enforcer.c enforcer/enforcer.h \
	enforcer/update_repositorylist_cmd.c enforcer/update_repositorylist_cmd.h \
	enforcer/repositorylist_cmd.c enforcer/repositorylist_cmd.h \
	enforcer/update_all_cmd.c enforcer/update_all_cmd.h \
	enforcer/update_conf_cmd.c enforcer/update_conf_cmd.h \
	utils/kc_helper.c utils/kc_helper.h \
	db/db_backend.c db/db_backend.h \
	db/db_clause.c db/db_clause.h \
	db/db_configuration.c db/db_configuration.h \
	db/db_connection.c db/db_connection.h \
	db/db_object.c db/db_object.h \
	db/db_result.c db/db_result.h \
	db/db_type.h \
	db/db_value.c db/db_value.h \
	db/db_join.c db/db_join.h \
	db/db_error.h \
	db/zone_db.c db/zone_db_ext.c db/zone_db_ext.h db/zone_db.h \
	db/key_data.c db/key_data_ext.c db/key_data_ext.h db/key_data.h \
	db/key_state.c db/key_state_ext.c db/key_state_ext.h db/key_state.h \
	db/key_dependency.c db/key_dependency_ext.c db/key_dependency_ext.h db/key_dependency.h \
	db/policy.c db/policy_ext.c db/policy_ext.h db/policy.h \
	db/policy_key.c db/policy_key_ext.c db/policy_key_ext.h db/policy_key.h \
	db/hsm_key.c db/hsm_key_ext.c db/hsm_key_ext.h db/hsm_key.h \
	db/database_version.c db/database_version.h db/database_version_ext.c db/database_version_ext.h \
	db/db_enum.h \
	$(BACKEND_SOURCES_CUSTOM)

ods_enforcerd_LDADD = \
	$(LIBHSM) \
	$(LIBCOMPAT) \
	@LDNS_LIBS@ \
	@XML2_LIBS@ \
	@PTHREAD_LIBS@ \
	@RT_LIBS@ \
	@ENFORCER_DB_LIBS@

ods_migrate_SOURCES = \
	ods-migrate.c \
	daemon/cfg.c daemon/cfg.h \
	daemon/engine.h \
	parser/confparser.c parser/confparser.h \
	utils/kc_helper.c utils/kc_helper.h

ods_migrate_LDADD = \
	$(LIBHSM) \
	$(LIBCOMPAT) \
	@LDNS_LIBS@ \
	@XML2_LIBS@ \
	@PTHREAD_LIBS@ \
	@RT_LIBS@ \
	@ENFORCER_DB_LIBS@

#ods_migrate_LDFLAGS = \
#	-Wl,--no-as-needed @ENFORCER_DB_LIBS@ -Wl,--as-needed

ods_enforcerd_LDFLAGS = \
	$(BACKEND_LDFLAGS_CUSTOM)

ods_enforcer_SOURCES = \
	ods-enforcer.c

ods_enforcer_LDADD = \
	$(LIBHSM) \
	$(LIBCOMPAT) \
	@LDNS_LIBS@ \
	@XML2_LIBS@ \
	@READLINE_LIBS@

ods_enforcer_db_setup_SOURCES = \
	ods-enforcer-db-setup.c \
	daemon/cfg.c daemon/cfg.h \
	parser/confparser.c parser/confparser.h \
	$(BACKEND_SCHEMA_CUSTOM)

ods_enforcer_db_setup_LDADD = \
	$(LIBHSM) \
	$(LIBCOMPAT) \
	@LDNS_LIBS@ \
	@XML2_LIBS@ \
	@PTHREAD_LIBS@ \
	@RT_LIBS@ \
	@ENFORCER_DB_LIBS@

ods_enforcer_db_setup_LDFLAGS = \
	$(BACKEND_LDFLAGS_CUSTOM)

ods_kaspcheck_SOURCES = utils/kaspcheck.c utils/kc_helper.c utils/kc_helper.h

ods_kaspcheck_LDADD = $(LIBHSM) $(LIBCOMPAT)
ods_kaspcheck_LDADD += @XML2_LIBS@
