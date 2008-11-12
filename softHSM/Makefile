CC = g++
PROGRAM = libsoftHSM.pkcs11.2.20.so
SOURCE = main.cpp
OBJECT = main.o
$(PROGRAM): $(SOURCE)
	$(CC) -fPIC -g -c -Wall $(SOURCE) -I.
	$(CC) -shared -Wl,-soname,$(PROGRAM) -o $(PROGRAM) $(OBJECT) -lc -lbotan
	rm $(OBJECT)
