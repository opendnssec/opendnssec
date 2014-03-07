CC=gcc
CXX=g++
CFLAGS=-g -c -Wall -I. -I..
CXXFLAGS=-g -c -Wall -I. -I..
LDFLAGS=
SOURCES=DbBackend.cpp DbBackendFactory.cpp DbBackendMySQL.cpp DbBackendSQLite.cpp DbConnection.cpp DbConnectionFactory.cpp DbObject.cpp DbObjects.cpp DbTransaction.cpp test.cpp
OBJECTS=$(SOURCES:.cpp=.o)
HEADERS=$(SOURCES:.cpp=.h)
EXECUTABLE=test

C_SOURCES=ctest.c db_backend.c db_backend_sqlite.c db_clause.c db_connection.c db_transaction.c db_type.c db_configuration.c db_result.c db_object.c
C_OBJECTS=$(C_SOURCES:.c=.o)
C_HEADERS=$(C_SOURCES:.c=.h)
C_EXECUTABLE=ctest


all: $(C_EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CXX) $(LDFLAGS) $(OBJECTS) -o $@

$(C_EXECUTABLE): $(C_OBJECTS) 
	$(CC) $(LDFLAGS) $(C_OBJECTS) -o $@

#.cpp.o:
%.o : %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) $< -o $@

%.o : %.c $(C_HEADERS)
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(OBJECTS) $(EXECUTABLE)
	rm -f $(C_OBJECTS) $(C_EXECUTABLE)
