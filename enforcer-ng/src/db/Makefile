CC=gcc
CFLAGS=-g -c -Wall -I. -I..
LDFLAGS=-lsqlite3
SOURCES=test.c db_backend.c db_backend_sqlite.c db_clause.c db_connection.c db_transaction.c db_type.c db_configuration.c db_result.c db_object.c db_value.c db_join.c
OBJECTS=$(SOURCES:.c=.o)
HEADERS=$(SOURCES:.c=.h)
EXECUTABLE=test

all: $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)

%.o : %.c $(HEADERS)
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(OBJECTS) $(EXECUTABLE)
