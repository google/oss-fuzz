TARGET=Fuzzer

#File
httpEXE=Fuzz_http
cloneEXE=Fuzz_clone

#Flags
INC=-I ../src -I ../build -I../src/test/
EXTCFLAGS=-Wall -Werror -g
LibINC=-L../build/
LibFLAGS=$(LIB_FUZZING_ENGINE) -lnxt

all: $(TARGET)

#SETUP
$(TARGET):
	$(CC)  $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(httpEXE).c
	$(CXX) $(CFLAGS) $(LibINC) -o $(httpEXE) $(httpEXE).o  $(LibFLAGS)

	$(CC)  $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(cloneEXE).c
	$(CXX) $(CFLAGS) $(LibINC) -o $(cloneEXE) $(cloneEXE).o  $(LibFLAGS)

clean:
	rm $(cloneEXE) $(httpEXE) *.o

.PHONY: all clean
