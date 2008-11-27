TARGET=		libsoftHSM.pkcs11.2.20.so
SOURCE=		main.cpp
OBJS=		main.o


CC=		g++

CPPFLAGS=	-I. -I/usr/local/include
CFLAGS=		-g -fPIC -Wall
LDFLAGS=	-shared -L/usr/local/lib
LIBS=		-lbotan

COMPILE=	$(CC) $(CPPFLAGS) $(CFLAGS)
LINK=		$(CC) $(CFLAGS) $(LDFLAGS) -dynamiclib


all: $(TARGET)

$(TARGET): $(SOURCE)
	$(COMPILE) -c $(SOURCE)
	$(LINK) -o $(TARGET) $(OBJS) $(LIBS)

clean:
	rm -f *.o
	rm -f $(TARGET)
