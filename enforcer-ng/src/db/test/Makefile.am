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

test_LDADD = \
	../../db_backend.o \
	../../db_backend_sqlite.o \
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
	rm -f test.db
	sqlite3 test.db < $(srcdir)/test.sqlite
	./test
