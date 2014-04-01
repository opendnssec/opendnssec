MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	-I$(top_srcdir)/common \
	-I$(top_builddir)/common \
	@ENFORCER_DB_INCLUDES@ \
	@CUNIT_INCLUDES@

check_PROGRAMS = test

test_SOURCES = \
	log.c \
	test.c \
	test_classes.c \
	test_initialization.c \
	test_database_operations.c

# TODO: if BACKEND test_LDADD+=backend.o

test_LDADD = \
	../../db_backend.o \
	../../db_backend_sqlite.o \
	../../db_backend_couchdb.o \
	../../db_clause.o \
	../../db_configuration.o \
	../../db_connection.o \
	../../db_join.o \
	../../db_object.o \
	../../db_result.o \
	../../db_type.o \
	../../db_value.o \
	$(top_builddir)/mm/src/mm.o

test_LDFLAGS = -no-install @CUNIT_LIBS@ @ENFORCER_DB_LIBS@

check: regress-db

regress-db: test
# TODO: if SQLITE
	rm -f test.db
	sqlite3 test.db < $(srcdir)/test.sqlite
# TODO: if COUCHDB
	curl -X DELETE http://127.0.0.1:5984/opendnssec
	curl -X PUT http://127.0.0.1:5984/opendnssec
	curl -X PUT http://127.0.0.1:5984/opendnssec/_design/application -d @$(srcdir)/test.couchdb
	./test
