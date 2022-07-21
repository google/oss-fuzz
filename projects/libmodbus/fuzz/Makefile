TARGET=AFL

#File
CLIENTEXE=FuzzClient
SERVEREXE=FuzzServer

#Compiler
LIBTOOL=libtool --mode=link --tag=CXX

#Compiler Flags
SET=cd ../ &&
INC=-I../src/
LIB=../src/libmodbus.la
EXTCFLAGS= -Wall -Wextra
CFLAGS=-g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS=-fsanitize=address,undefined

all: $(TARGET)

#SETUP
INIT:
	$(SET) ./autogen.sh

CONF:
	$(SET) ./configure --disable-shared CC=$(CC) CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)"

MAKEALL:
	$(SET) make -j$(nproc)

CPFILE:
	cp ../tests/unit-test.h .

$(TARGET): INIT CONF MAKEALL CPFILE
	$(CC) $(EXTCFLAGS) $(CFLAGS) $(INC) -c $(CLIENTEXE).c
	$(LIBTOOL) $(CC) $(LDFLAGS) $(CLIENTEXE).o -o $(CLIENTEXE) $(LIB)

	$(CC) $(EXTCFLAGS) $(CFLAGS) $(INC) -c $(SERVEREXE).c
	$(LIBTOOL) $(CC) $(LDFLAGS) $(SERVEREXE).o -o $(SERVEREXE) $(LIB)

clean:
	rm $(CLIENTEXE) $(SERVEREXE) *.o

.PHONY: all AFL clean
