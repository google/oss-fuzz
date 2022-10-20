TARGET=Fuzzing
INCDIR=-I..
LIBDIR=-L..
EXTFLAGS=-Wall -Werror
LibFLAGS=$(LIB_FUZZING_ENGINE)

BaseINC=$(INCDIR)/proxy/api $(INCDIR)/proxy/api $(INCDIR)/include/cppapi/include \
	$(INCDIR)/lib/cppapi/include $(INCDIR)/include $(INCDIR)/lib

BaseMACRO=-DHAVE_CONFIG_H -Dlinux -D_LARGEFILE64_SOURCE=1 -D_COMPILE64BIT_SOURCE=1 -D_REENTRANT \
	-D__STDC_LIMIT_MACROS=1 -D__STDC_FORMAT_MACROS=1 -D_GNU_SOURCE -DOPENSSL_NO_SSL_INTERN \
	-DOPENSSL_API_COMPAT=10002 -DOPENSSL_IS_OPENSSL3

EsiEXE=FuzzEsi
EsiINC=$(INCDIR)/include $(INCDIR)/plugins/esi/ $(INCDIR)/plugins/esi/lib/ $(INCDIR)/plugins/esi/fetcher/
EsiLib=$(LIBDIR)/plugins/esi/.libs/
EsiLIB=$(LibFLAGS) -ltest -lesicore -lz

all: $(TARGET)

$(TARGET):
	$(CXX) $(CXXFLAGS) $(EXTFLAGS) $(BaseMACRO) $(EsiINC) $(BaseINC) -c $(EsiEXE).cc
	$(CXX) $(CXXFLAGS) $(EsiLib) -o $(EsiEXE) $(EsiEXE).o $(EsiLIB)

clean:
	rm $(EsiEXE) *.o

.PHONY: all clean
