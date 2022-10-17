TARGET=Fuzzing

PropRecvEXE=FuzzPropRecv
ReqResEXE=FuzzReqRes

INC=-I../include/
EXTCFLAGS=-g -Wall -pthread
#-Werror
LibINC=-L../lib/
LibFLAGS=$(LIB_FUZZING_ENGINE) -lmosquitto -lssl -lcrypto

all: $(TARGET)

$(TARGET):
	$(CC) $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(PropRecvEXE).c
	$(CXX) $(CFLAGS) $(LibINC) -o $(PropRecvEXE) $(PropRecvEXE).o $(LibFLAGS)

	$(CC) $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(ReqResEXE).c
	$(CXX) $(CFLAGS) $(LibINC) -o $(ReqResEXE) $(ReqResEXE).o $(LibFLAGS)

clean:
	rm $(PropRecvEXE) $(ReqResEXE) *.o

.PHONY: all clean
