CC=g++
CFLAGS=-g -c -Wall -I. -I..
LDFLAGS=
SOURCES=DbBackend.cpp DbBackendFactory.cpp DbBackendMySQL.cpp DbBackendSQLite.cpp DbConnection.cpp DbConnectionFactory.cpp DbObject.cpp DbObjects.cpp DbTransaction.cpp test.cpp
OBJECTS=$(SOURCES:.cpp=.o)
HEADERS=$(SOURCES:.cpp=.h)
EXECUTABLE=test

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

#.cpp.o:
%.o : %.cpp $(HEADERS)
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm $(OBJECTS) $(EXECUTABLE)
