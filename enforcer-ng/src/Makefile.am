# $Id$

LIBCOMPAT = ${top_builddir}/common/libcompat.a

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

BUILT_SOURCES = \
	$(srcdir)/xmlext-pb/xmlext.pb.cc $(srcdir)/xmlext-pb/xmlext.pb.h \
	$(srcdir)/hsmkey/hsmkey.pb.cc $(srcdir)/hsmkey/hsmkey.pb.h \
	$(srcdir)/keystate/keystate.pb.cc $(srcdir)/keystate/keystate.pb.h \
	$(srcdir)/parser/conf.pb.cc $(srcdir)/parser/conf.pb.h \
	$(srcdir)/policy/kasp.pb.cc $(srcdir)/policy/kasp.pb.h \
	$(srcdir)/signconf/signconf.pb.cc $(srcdir)/signconf/signconf.pb.h \
	$(srcdir)/protobuf-orm/orm.pb.cc $(srcdir)/protobuf-orm/orm.pb.h

EXTRA_DIST = \
	$(srcdir)/xmlext-pb/xmlext.proto \
	$(srcdir)/hsmkey/hsmkey.proto \
	$(srcdir)/keystate/keystate.proto \
	$(srcdir)/parser/conf.proto \
	$(srcdir)/policy/kasp.proto \
	$(srcdir)/signconf/signconf.proto \
	$(srcdir)/protobuf-orm/orm.proto

CLEANFILES = $(BUILT_SOURCES)

LIBHSM = ${top_builddir}/libhsm/src/lib/libhsm.a

SUBDIRS = protobuf-orm/test

AM_CPPFLAGS = \
	-I$(top_srcdir)/common \
	-I$(top_builddir)/common \
	-I$(srcdir)/../../libhsm/src/lib \
	-I$(builddir)/../../libhsm/src/lib \
	-I$(srcdir)/xmlext-pb \
	-I$(srcdir)/protobuf-orm \
	@XML2_INCLUDES@ \
	@LDNS_INCLUDES@ \
	@PROTOBUF_INCLUDES@ \
	@ENFORCER_DB_INCLUDES@

enforcerdir =	@libdir@/opendnssec/enforcer

sbin_PROGRAMS =	ods-enforcerd ods-enforcer
# man8_MANS =	man/ods-enforcer.8 man/ods-enforcerd.8

nodist_ods_enforcerd_SOURCES = $(BUILT_SOURCES)

ods_enforcerd_SOURCES = \
	ods-enforcerd.c \
	daemon/cfg.c daemon/cfg.h \
	daemon/cmdhandler.c daemon/cmdhandler.h \
	daemon/engine.c daemon/engine.h \
	daemon/signal.c daemon/signal.h \
	daemon/worker.c daemon/worker.h \
	daemon/orm.cpp daemon/orm.h \
	parser/confparser.c parser/confparser.h \
	scheduler/fifoq.c scheduler/fifoq.h \
	scheduler/schedule.c scheduler/schedule.h \
	scheduler/task.c scheduler/task.h \
	shared/allocator.c shared/allocator.h \
	shared/duration.c shared/duration.h \
	shared/file.c shared/file.h \
	shared/hsm.c shared/hsm.h \
	shared/locks.c shared/locks.h \
	shared/log.c shared/log.h \
	shared/privdrop.c shared/privdrop.h \
	shared/status.c shared/status.h \
	shared/util.c shared/util.h \
	shared/str.c shared/str.h \
	shared/backup.c shared/backup.h \
	shared/keys.c shared/keys.h \
	shared/protobuf.cpp shared/protobuf.h \
	xmlext-pb/xmlext-rd.cpp xmlext-pb/xmlext-rd.h \
	xmlext-pb/xmlext-wr.cpp xmlext-pb/xmlext-wr.h \
	policy/update_kasp_cmd.cpp policy/update_kasp_cmd.h \
	policy/update_kasp_task.cpp policy/update_kasp_task.h \
	policy/policy_list_cmd.cpp policy/policy_list_cmd.h \
	policy/policy_list_task.cpp policy/policy_list_task.h \
	policy/policy_resalt_cmd.cpp policy/policy_resalt_cmd.h \
	policy/policy_resalt_task.cpp policy/policy_resalt_task.h \
	policy/resalt.cpp policy/resalt.h \
	hsmkey/hsmkey_gen_cmd.cpp hsmkey/hsmkey_gen_cmd.h \
	hsmkey/hsmkey_gen_task.cpp hsmkey/hsmkey_gen_task.h \
	hsmkey/hsmkey_list_cmd.cpp hsmkey/hsmkey_list_cmd.h \
	hsmkey/hsmkey_list_task.cpp hsmkey/hsmkey_list_task.h \
	hsmkey/backup_hsmkeys_cmd.cpp hsmkey/backup_hsmkeys_cmd.h \
	hsmkey/backup_hsmkeys_task.cpp hsmkey/backup_hsmkeys_task.h \
	hsmkey/update_hsmkeys_cmd.cpp hsmkey/update_hsmkeys_cmd.h \
	hsmkey/update_hsmkeys_task.cpp hsmkey/update_hsmkeys_task.h \
	keystate/zone_list_cmd.cpp keystate/zone_list_cmd.h \
	keystate/zone_list_task.cpp keystate/zone_list_task.h \
	keystate/zone_export_cmd.cpp keystate/zone_export_cmd.h \
	keystate/zone_export_task.cpp keystate/zone_export_task.h \
	keystate/zone_add_cmd.cpp keystate/zone_add_cmd.h \
	keystate/zone_add_task.cpp keystate/zone_add_task.h \
	keystate/zone_del_cmd.cpp keystate/zone_del_cmd.h \
	keystate/zone_del_task.cpp keystate/zone_del_task.h \
	keystate/keystate_list_cmd.cpp keystate/keystate_list_cmd.h \
	keystate/keystate_list_task.cpp keystate/keystate_list_task.h \
	keystate/rollover_list_cmd.cpp keystate/rollover_list_cmd.h \
	keystate/rollover_list_task.cpp keystate/rollover_list_task.h \
	keystate/keystate_export_cmd.cpp keystate/keystate_export_cmd.h \
	keystate/keystate_export_task.cpp keystate/keystate_export_task.h \
	keystate/keystate_ds_submit_cmd.cpp keystate/keystate_ds_submit_cmd.h \
	keystate/keystate_ds_submit_task.cpp keystate/keystate_ds_submit_task.h \
	keystate/keystate_ds_seen_cmd.cpp keystate/keystate_ds_seen_cmd.h \
	keystate/keystate_ds_seen_task.cpp keystate/keystate_ds_seen_task.h \
	keystate/keystate_ds_retract_cmd.cpp keystate/keystate_ds_retract_cmd.h \
	keystate/keystate_ds_retract_task.cpp keystate/keystate_ds_retract_task.h \
	keystate/keystate_ds_gone_cmd.cpp keystate/keystate_ds_gone_cmd.h \
	keystate/keystate_ds_gone_task.cpp keystate/keystate_ds_gone_task.h \
	keystate/update_keyzones_cmd.cpp keystate/update_keyzones_cmd.h \
	keystate/update_keyzones_task.cpp keystate/update_keyzones_task.h \
	keystate/keystate_rollover_cmd.cpp keystate/keystate_rollover_cmd.h \
	keystate/keystate_rollover_task.cpp keystate/keystate_rollover_task.h \
	keystate/zonelist_task.h keystate/zonelist_task.cpp \
	keystate/zonelist_cmd.h keystate/zonelist_cmd.cpp \
	keystate/write_signzone_task.h keystate/write_signzone_task.cpp \
	signconf/signconf_cmd.cpp signconf/signconf_cmd.h \
	signconf/signconf_task.cpp signconf/signconf_task.h \
	enforcer/enforcerdata.h \
	enforcer/autostart_cmd.cpp enforcer/autostart_cmd.h \
	enforcer/setup_cmd.cpp enforcer/setup_cmd.h \
	enforcer/enforce_cmd.cpp enforcer/enforce_cmd.h \
	enforcer/enforce_task.cpp enforcer/enforce_task.h \
	enforcer/enforcer.cpp enforcer/enforcer.h \
	enforcer/enforcerzone.cpp enforcer/enforcerzone.h \
	enforcer/hsmkeyfactory.cpp enforcer/hsmkeyfactory.h \
	enforcer/update_conf_cmd.cpp enforcer/update_conf_cmd.h \
	enforcer/update_conf_task.cpp enforcer/update_conf_task.h \
	enforcer/update_all_cmd.cpp enforcer/update_all_cmd.h \
	protobuf-orm/pb-orm.h \
	protobuf-orm/pb-orm-common.h \
	protobuf-orm/pb-orm-connect.cc protobuf-orm/pb-orm-connect.h \
	protobuf-orm/pb-orm-context.cc protobuf-orm/pb-orm-context.h \
	protobuf-orm/pb-orm-create-table.cc protobuf-orm/pb-orm-create-table.h \
	protobuf-orm/pb-orm-create.cc protobuf-orm/pb-orm-create.h \
	protobuf-orm/pb-orm-database-helper.cc protobuf-orm/pb-orm-database-helper.h \
	protobuf-orm/pb-orm-database-sqlite3.cc protobuf-orm/pb-orm-database-sqlite3.h \
	protobuf-orm/pb-orm-database-mysql.cc protobuf-orm/pb-orm-database-mysql.h \
	protobuf-orm/pb-orm-database.cc protobuf-orm/pb-orm-database.h \
	protobuf-orm/pb-orm-datastore.cc protobuf-orm/pb-orm-datastore.h \
	protobuf-orm/pb-orm-delete.cc protobuf-orm/pb-orm-delete.h \
	protobuf-orm/pb-orm-drop-table.cc protobuf-orm/pb-orm-drop-table.h \
	protobuf-orm/pb-orm-enum.cc protobuf-orm/pb-orm-enum.h \
	protobuf-orm/pb-orm-initialize.cc protobuf-orm/pb-orm-initialize.h \
	protobuf-orm/pb-orm-log.cc protobuf-orm/pb-orm-log.h \
	protobuf-orm/pb-orm-read.cc protobuf-orm/pb-orm-read.h \
	protobuf-orm/pb-orm-shutdown.cc protobuf-orm/pb-orm-shutdown.h \
	protobuf-orm/pb-orm-str.cc protobuf-orm/pb-orm-str.h \
	protobuf-orm/pb-orm-transaction.cc protobuf-orm/pb-orm-transaction.h \
	protobuf-orm/pb-orm-update.cc protobuf-orm/pb-orm-update.h \
	protobuf-orm/pb-orm-value.cc protobuf-orm/pb-orm-value.h

ods_enforcerd_LDADD = \
	$(LIBHSM) \
    $(LIBCOMPAT) \
	@LDNS_LIBS@ \
	@XML2_LIBS@ \
	@PTHREAD_LIBS@ \
	@RT_LIBS@ \
	@PROTOBUF_LIBS@ \
	@ENFORCER_DB_LIBS@

ods_enforcer_SOURCES = \
	ods-enforcer.c \
	shared/allocator.c shared/allocator.h \
	shared/duration.c shared/duration.h \
	shared/file.c shared/file.h \
	shared/log.c shared/log.h \
	shared/util.c shared/util.h \
	shared/str.c shared/str.h

ods_enforcer_LDADD = \
	$(LIBHSM) \
	@LDNS_LIBS@ \
	@XML2_LIBS@ \
	@READLINE_LIBS@

%.pb.cc %.pb.h: %.proto
	$(PROTOC) @PROTOBUF_INCLUDES@ -I$(srcdir)/xmlext-pb -I$(srcdir)/protobuf-orm --cpp_out=`dirname $@` -I=`dirname $<` $<
