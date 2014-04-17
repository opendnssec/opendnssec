MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	-I$(top_srcdir)/common \
	-I$(top_builddir)/common \
	@ENFORCER_DB_INCLUDES@ \
	@CUNIT_INCLUDES@

check_PROGRAMS = test

test_SOURCES = \
	log.c \
	test.c test.h \
	test_classes.c \
	test_initialization.c \
	test_database_operations.c \
	test_adapter.c test_adapter.h \
	test_adapters.c test_adapters.h \
	test_audit.c test_audit.h \
	test_dbo_hsm_key.c test_dbo_hsm_key.h \
	test_dbo_keylist.c test_dbo_keylist.h \
	test_denial.c test_denial.h \
	test_enforcer_zone.c test_enforcer_zone.h \
	test_hsm_key_used_by_zones.c test_hsm_key_used_by_zones.h \
	test_key_data.c test_key_data.h \
	test_key_dependency.c test_key_dependency.h \
	test_key_state.c test_key_state.h \
	test_ksk.c test_ksk.h \
	test_nsec3.c test_nsec3.h \
	test_nsec.c test_nsec.h \
	test_parent.c test_parent.h \
	test_policy.c test_policy.h \
	test_signatures.c test_signatures.h \
	test_zone.c test_zone.h \
	test_zsk.c test_zsk.h

if USE_SQLITE
BACKEND_LDADD_CUSTOM = ../../db_backend_sqlite.o
endif

if USE_COUCHDB
BACKEND_LDADD_CUSTOM = ../../db_backend_couchdb.o
BACKEND_LDFLAGS_CUSTOM = \
	`pkg-config --libs libcurl` \
	`pkg-config --libs jansson`
endif

test_LDADD = \
	../../db_backend.o \
	../../db_clause.o \
	../../db_configuration.o \
	../../db_connection.o \
	../../db_join.o \
	../../db_object.o \
	../../db_result.o \
	../../db_type.o \
	../../db_value.o \
	$(top_builddir)/mm/src/mm.o \
	../../adapter.o ../../adapter_ext.o \
	../../adapters.o ../../adapters_ext.o \
	../../audit.o ../../audit_ext.o \
	../../dbo_hsm_key.o ../../dbo_hsm_key_ext.o \
	../../dbo_keylist.o ../../dbo_keylist_ext.o \
	../../denial.o ../../denial_ext.o \
	../../enforcer_zone.o ../../enforcer_zone_ext.o \
	../../hsm_key_used_by_zones.o ../../hsm_key_used_by_zones_ext.o \
	../../key_data.o ../../key_data_ext.o \
	../../key_dependency.o ../../key_dependency_ext.o \
	../../key_state.o ../../key_state_ext.o \
	../../ksk.o ../../ksk_ext.o \
	../../nsec3.o ../../nsec3_ext.o \
	../../nsec.o ../../nsec_ext.o \
	../../parent.o ../../parent_ext.o \
	../../policy.o ../../policy_ext.o \
	../../signatures.o ../../signatures_ext.o \
	../../zone.o ../../zone_ext.o \
	../../zsk.o ../../zsk_ext.o \
	$(BACKEND_LDADD_CUSTOM)

test_LDFLAGS = -no-install \
	@CUNIT_LIBS@ \
	@ENFORCER_DB_LIBS@ \
	$(BACKEND_LDFLAGS_CUSTOM)

check: regress-db

regress-db: test
if USE_SQLITE
	rm -f test.db
	sqlite3 test.db < $(srcdir)/test.sqlite
endif
if USE_COUCHDB
	curl -X DELETE http://127.0.0.1:5984/opendnssec
	curl -X PUT http://127.0.0.1:5984/opendnssec
	curl -X PUT http://127.0.0.1:5984/opendnssec/_design/application -d @$(srcdir)/test.couchdb
	curl -X PUT http://127.0.0.1:5984/opendnssec/1 -d '{"type":"test","test_name":"test"}'
endif
	./test
