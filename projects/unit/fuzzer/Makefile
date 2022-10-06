TARGET=Fuzzer

#FileEXE
httpEXE=Fuzz_http
jsonEXE=Fuzz_json

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

	$(CC)  $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(jsonEXE).c
	$(CXX) $(CFLAGS) $(LibINC) -o $(jsonEXE) $(jsonEXE).o  $(LibFLAGS)

clean:
	rm $(jsonEXE) $(httpEXE) *.o

.PHONY: all clean
