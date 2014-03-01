MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = \
	-I$(top_srcdir)/common \
	-I$(top_builddir)/common \
	-I$(srcdir)/../../xmlext-pb \
	-I$(srcdir)/../../protobuf-orm \
	@PROTOBUF_INCLUDES@ \
	@ENFORCER_DB_INCLUDES@ \
	`cppunit-config --cflags`

EXTRA_DIST = 			big.proto \
						product.proto \
						tree.proto \
						zone.proto

CLEANFILES =			big.pb.cc big.pb.h \
						product.pb.cc product.pb.h \
						tree.pb.cc tree.pb.h \
						zone.pb.cc zone.pb.h \
						benchmark.rtf \
						sample_db

check_PROGRAMS = 		pbormtest

pbormtest_SOURCES =		big.pb.cc big.pb.h \
						product.pb.cc product.pb.h \
						tree.pb.cc tree.pb.h \
						zone.pb.cc zone.pb.h \
						pbormtest.cc pbormtest.h \
						timecollector.cc timecollector.h \
						pb-orm-big-tests.cc pb-orm-big-tests.h \
						pb-orm-tree-tests.cc pb-orm-tree-tests.h \
						pb-orm-producer-tests.cc pb-orm-producer-tests.h \
						pb-orm-zone-tests.cc pb-orm-zone-tests.h

pbormtest_LDADD =		../../pb-orm-connect.o \
						../../pb-orm-context.o \
						../../pb-orm-create.o \
						../../pb-orm-create-table.o \
						../../pb-orm-database-helper.o \
						../../pb-orm-database-mysql.o \
						../../pb-orm-database.o \
						../../pb-orm-database-sqlite3.o \
						../../pb-orm-datastore.o \
						../../pb-orm-delete.o \
						../../pb-orm-drop-table.o \
						../../pb-orm-enum.o \
						../../pb-orm-initialize.o \
						../../pb-orm-log.o \
						../../pb-orm-read.o \
						../../pb-orm-shutdown.o \
						../../pb-orm-str.o \
						../../pb-orm-transaction.o \
						../../pb-orm-update.o \
						../../pb-orm-value.o

pbormtest_LDADD +=		../../conf.pb.o \
						../../hsmkey.pb.o \
						../../kasp.pb.o \
						../../keystate.pb.o \
						../../orm.pb.o \
						../../signconf.pb.o \
						../../xmlext.pb.o

pbormtest_LDFLAGS = 	-no-install `cppunit-config --libs` \
						@PTHREAD_LIBS@ \
						@RT_LIBS@ \
						@PROTOBUF_LIBS@ \
						@ENFORCER_DB_LIBS@

%.pb.cc %.pb.h: %.proto
	$(PROTOC) @PROTOBUF_INCLUDES@ -I$(srcdir)/../../xmlext-pb -I$(srcdir)/../../protobuf-orm --cpp_out=`dirname $@` -I=`dirname $<` $<

check: regress-pb-orm

regress-pb-orm: pbormtest
	./pbormtest
