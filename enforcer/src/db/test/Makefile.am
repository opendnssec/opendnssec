MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	-I$(top_srcdir)/common \
	-I$(top_builddir)/common \
	@ENFORCER_DB_INCLUDES@ \
	@CUNIT_INCLUDES@ \
	@XML2_INCLUDES@

check_PROGRAMS = test

test_SOURCES = \
	test.c test.h \
	test_classes.c \
	test_initialization.c \
	test_database_operations.c \
	test_hsm_key.c test_hsm_key.h \
	test_key_data.c test_key_data.h \
	test_key_state.c test_key_state.h \
	test_key_dependency.c test_key_dependency.h \
	test_policy.c test_policy.h \
	test_policy_key.c test_policy_key.h \
	test_database_version.c test_database_version.h \
	test_zone.c test_zone.h

BACKEND_LDADD_CUSTOM =
BACKEND_LDFLAGS_CUSTOM =

if USE_SQLITE
BACKEND_LDADD_CUSTOM += ../db_backend_sqlite.o
endif

if USE_MYSQL
BACKEND_LDADD_CUSTOM += ../db_backend_mysql.o
endif

test_LDADD = \
	../db_backend.o \
	../db_clause.o \
	../db_configuration.o \
	../db_connection.o \
	../db_join.o \
	../db_object.o \
	../db_result.o \
	../db_value.o \
	../hsm_key.o ../hsm_key_ext.o \
	../key_data.o ../key_data_ext.o \
	../key_state.o \
	../key_dependency.o \
	../policy.o ../policy_ext.o \
	../policy_key.o ../policy_key_ext.o \
	../database_version.o ../database_version_ext.o \
	../zone_db.o ../zone_db_ext.o \
	${top_builddir}/common/duration.o \
	${top_builddir}/common/log.o \
	${top_builddir}/common/file.o \
	$(BACKEND_LDADD_CUSTOM)

test_LDFLAGS = -no-install \
	@XML2_LIBS@ \
	@PTHREAD_LIBS@ \
	@RT_LIBS@ \
	@CUNIT_LIBS@ \
	@ENFORCER_DB_LIBS@ \
	$(BACKEND_LDFLAGS_CUSTOM)

check: regress-db

regress-db: test
if USE_SQLITE
	rm -f test.db
	sqlite3 test.db < $(srcdir)/test.sqlite
	sqlite3 test.db < $(srcdir)/../schema.sqlite
	sqlite3 test.db < $(srcdir)/../data.sqlite
endif
if USE_MYSQL
	mysql -u "@ENFORCER_DB_USERNAME@" "-p@ENFORCER_DB_PASSWORD@" "@ENFORCER_DB_DATABASE@" < $(srcdir)/test.mysql
	mysql -u "@ENFORCER_DB_USERNAME@" "-p@ENFORCER_DB_PASSWORD@" "@ENFORCER_DB_DATABASE@" < $(srcdir)/../drop.mysql
	mysql -u "@ENFORCER_DB_USERNAME@" "-p@ENFORCER_DB_PASSWORD@" "@ENFORCER_DB_DATABASE@" < $(srcdir)/../schema.mysql
	mysql -u "@ENFORCER_DB_USERNAME@" "-p@ENFORCER_DB_PASSWORD@" "@ENFORCER_DB_DATABASE@" < $(srcdir)/../data.mysql
endif
	./test
