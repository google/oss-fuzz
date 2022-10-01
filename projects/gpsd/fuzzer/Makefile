TARGET=Fuzzer

#File
jsonEXE=FuzzJson
packetEXE=FuzzPacket
libgpsEXE=FuzzLibgps

#Compiler Flags
DIR=$(shell ls -d ../gpsd*~dev/)
INC=-I$(DIR)include/ -I/usr/include/libusb-1.0
EXTCFLAGS=-Wall -Werror -pthread
LibINC=-L$(DIR)
LibFLAGS=$(LIB_FUZZING_ENGINE) -lgpsd -lgps_static

all: $(TARGET)

#SETUP
$(TARGET):
	$(CC) $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(jsonEXE).c
	$(CC) $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(packetEXE).c
	$(CC) $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(libgpsEXE).c

	$(CXX) $(CFLAGS) $(LibINC) -o $(jsonEXE) $(jsonEXE).o  $(LibFLAGS)
	$(CXX) $(CFLAGS) $(LibINC) -o $(packetEXE) $(packetEXE).o  $(LibFLAGS)
	$(CXX) $(CFLAGS) $(LibINC) -o $(libgpsEXE) $(libgpsEXE).o  $(LibFLAGS)

clean:
	rm $(jsonEXE) $(packetEXE) $(libgpsEXE) *.o

.PHONY: all clean
