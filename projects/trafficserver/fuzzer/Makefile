TARGET=Fuzzing
INCDIR=-I..
LIBDIR=-L..
EXTCFLAGS=-g -Wall -Werror -std=c++17 -pipe
LibFLAGS=$(LIB_FUZZING_ENGINE)

EsiEXE=FuzzEsi
EsiINC=$(INCDIR)/plugins/esi/lib/ $(INCDIR)/plugins/esi/
EsiLib=$(LIBDIR)/plugins/esi/.libs/
EsiLIB=$(LibFLAGS) -lesicore

all: $(TARGET)

$(TARGET):
	$(CXX) $(CFLAGS) $(EsiINC) $(EXTCFLAGS) -c $(EsiEXE).cc
	$(CXX) $(CFLAGS) $(EsiLib) $(EXTCFLAGS) -o $(EsiEXE) $(EsiEXE).o $(EsiLIB)

clean:
	rm $(EsiEXE) *.o

.PHONY: all clean
