TARGET=Fuzzer

#EXEFuzzer
FUZZEREXE=FuzzStun

#Flags
SET=cd ../ &&
EXTCFLAGS= -Wall -Wextra
INC=-I../src -I../src/apps/common -I../src/server -I../src/client -I../src/client++ 
LIBINC=-L../lib/ -lturnclient
LIB=$(LIBINC) -lssl -lcrypto

all: $(TARGET)

CONF:
	$(SET) CC=$(CC) CFLAGS="$(CFLAGS)" LDFLAGS="$(CFLAGS)" ./configure 
MAKEALL:
	$(SET) make all 

$(TARGET): CONF MAKEALL
	$(CC) $(EXTCFLAGS) $(CFLAGS) $(INC) -c $(FUZZEREXE).c
	$(CXX) $(LDFLAGS) $(CFLAGS) $(LIB_FUZZING_ENGINE) $(FUZZEREXE).o -o $(FUZZEREXE) $(LIB)

clean:
	rm $(FUZZEREXE) *.o

reallyclean: clean
	$(SET) make clean

.PHONY: all clean reallyclean
