TARGET=Fuzzer

#File
jsonEXE=FuzzJson
packetEXE=FuzzPacket

#Compiler Flags
DIR=$(shell ls -d ../gpsd*~dev/)
INC=-I$(DIR)include/
EXTCFLAGS=-Wall -Werror -pthread -std=c99
LibINC=-L$(DIR)
LibFLAGS=$(LIB_FUZZING_ENGINE) -lgpsd -lgps_static

all: $(TARGET)

#SETUP
$(TARGET):
	$(CC) $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(jsonEXE).c
	$(CC) $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(packetEXE).c

	$(CXX) $(CFLAGS) $(LibINC) -o $(jsonEXE) $(jsonEXE).o  $(LibFLAGS)
	$(CXX) $(CFLAGS) $(LibINC) -o $(packetEXE) $(packetEXE).o  $(LibFLAGS)

clean:
	rm $(jsonEXE) $(packetEXE) *.o

.PHONY: all clean
