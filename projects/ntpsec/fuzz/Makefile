#main
TARGET=Fuzzer

#fuzzers
CLIENTEXE=FuzzClient
EXTENSEXE=FuzzExtens
SERVEREXE=FuzzServer

#Flags
SET=cd ../ &&
EXTCFLAGS= -Wall -Wextra
INC=-I../include/ -I../ntpd/ -I../build/ -I../tests/unity/ -I../tests/common/
LIBINC=../build/main

#library
ntpd_lib=-L$(LIBINC)/ntpd/ -lntpd_lib
libntp=-L$(LIBINC)/libntp/ -lntp
libaes_siv=-L$(LIBINC)/libaes_siv/ -laes_siv
extra_lib=-lssl -lcrypto
setup_inc=setup.o
LIB=$(ntpd_lib) $(libntp) $(libaes_siv) $(extra_lib) $(setup_inc)

all: $(TARGET)

INIT:
	$(SET) ./buildprep -n
CONF:
	$(SET) CC=$(CC) CFLAGS="$(CFLAGS)" LDFLAGS="$(CFLAGS)" ./waf configure --enable-debug --disable-doc
MAKEALL:
	$(SET) ./waf build --notests
SETUP:
	$(CC) $(EXTCFLAGS) $(CFLAGS) $(INC) -c setup.c

$(TARGET): INIT CONF MAKEALL SETUP
	$(CC) $(EXTCFLAGS) $(CFLAGS) $(INC) -c $(CLIENTEXE).c
	$(CC) $(EXTCFLAGS) $(CFLAGS) $(INC) -c $(EXTENSEXE).c
	$(CC) $(EXTCFLAGS) $(CFLAGS) $(INC) -c $(SERVEREXE).c

	$(CXX) $(LDFLAGS) $(CFLAGS) $(LIB_FUZZING_ENGINE) $(CLIENTEXE).o -o $(CLIENTEXE) $(LIB) 
	$(CXX) $(LDFLAGS) $(CFLAGS) $(LIB_FUZZING_ENGINE) $(EXTENSEXE).o -o $(EXTENSEXE) $(LIB) 
	$(CXX) $(LDFLAGS) $(CFLAGS) $(LIB_FUZZING_ENGINE) $(SERVEREXE).o -o $(SERVEREXE) $(LIB) 

clean:
	rm $(CLIENTEXE) $(EXTENSEXE) $(SERVEREXE) *.o

reallyclean: clean
	$(SET) ./waf clean

.PHONY: all clean reallyclean
