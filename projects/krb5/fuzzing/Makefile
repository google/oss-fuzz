TARGET=Fuzzer

#File
ndrEXE=Fuzz_ndr
pacEXE=Fuzz_pac
chpwEXE=Fuzz_chpw
jsonEXE=Fuzz_json
krb5EXE=Fuzz_krb5
marshalEXE=Fuzz_marshal
profileEXE=Fuzz_profile
gss_accept_sec_contextEXE=Fuzz_gss_accept_sec_context

#header lib obj
DIR=./../src
INC=-I$(DIR)/include/ -I$(DIR)/kdc/ -I$(DIR)/lib/krb5/ccache/ -I$(DIR)/util/profile/
EXTCFLAGS=-DHAVE_CONFIG_H -DKRB5_DEPRECATED=1 -DKRB5_PRIVATE -DHAS_STDARG -fcommon -Wall -Werror 

LibINC=-L$(DIR)/lib/ -fcommon
LibFLAGS=$(LIB_FUZZING_ENGINE) -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err -lkrb5support -lresolv
ndrOBJ=$(DIR)/kdc/ndr.o

all: $(TARGET)

#SETUP
$(TARGET):
	$(CC) $(CFLAGS) $(EXTCFLAGS) $(INC) -c $(ndrEXE).c
	$(CC) $(CFLAGS) $(EXTCFLAGS) $(INC) -c $(pacEXE).c
	$(CC) $(CFLAGS) $(EXTCFLAGS) $(INC) -c $(chpwEXE).c
	$(CC) $(CFLAGS) $(EXTCFLAGS) $(INC) -c $(jsonEXE).c
	$(CC) $(CFLAGS) $(EXTCFLAGS) $(INC) -c $(krb5EXE).c
	$(CC) $(CFLAGS) $(EXTCFLAGS) $(INC) -c $(marshalEXE).c
	$(CC) $(CFLAGS) $(EXTCFLAGS) $(INC) -c $(profileEXE).c
	$(CC) $(CFLAGS) $(EXTCFLAGS) $(INC) -c $(gss_accept_sec_contextEXE).c

	$(CXX) $(CFLAGS) $(LibINC) -o $(ndrEXE) $(ndrEXE).o $(ndrOBJ) $(LibFLAGS) 
	$(CXX) $(CFLAGS) $(LibINC) -o $(pacEXE) $(pacEXE).o $(LibFLAGS)
	$(CXX) $(CFLAGS) $(LibINC) -o $(chpwEXE) $(chpwEXE).o $(LibFLAGS)
	$(CXX) $(CFLAGS) $(LibINC) -o $(jsonEXE) $(jsonEXE).o $(LibFLAGS)
	$(CXX) $(CFLAGS) $(LibINC) -o $(krb5EXE) $(krb5EXE).o  $(LibFLAGS)
	$(CXX) $(CFLAGS) $(LibINC) -o $(marshalEXE) $(marshalEXE).o $(LibFLAGS)
	$(CXX) $(CFLAGS) $(LibINC) -o $(profileEXE) $(profileEXE).o $(LibFLAGS)
	$(CXX) $(CFLAGS) $(LibINC) -o $(gss_accept_sec_contextEXE) $(gss_accept_sec_contextEXE).o $(LibFLAGS)

clean:
	rm $(ndrEXE) $(pacEXE) $(chpwEXE) $(jsonEXE)  $(krb5EXE) $(marshalEXE) $(profileEXE) $(gss_accept_sec_contextEXE) *.o

.PHONY: all clean
