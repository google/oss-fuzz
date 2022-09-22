TARGET=Fuzzer

#File
ndrEXE=Fuzz_ndr
pacEXE=Fuzz_pac
chpwEXE=Fuzz_chpw
jsonEXE=Fuzz_json
marshalEXE=Fuzz_marshal
profileEXE=Fuzz_profile
rdreqEXE=Fuzz_rdreq

#Compiler Flags
INC=-I../src/include/ -I../src/kdc/ -I../src/lib/krb5/ccache/ -I../src/util/profile/
EXTCFLAGS=-DHAVE_CONFIG_H -DKRB5_DEPRECATED=1 -DKRB5_PRIVATE -fcommon -pthread -Wall -Werror 
LibINC=-L../src/lib/ -Wl,--enable-new-dtags -fcommon
LibFLAGS=$(LIB_FUZZING_ENGINE) -lkrb5 -lk5crypto -lcom_err -lkrb5support -lresolv

#Custom
ndrOBJ=../src/kdc/ndr.o
pacOBJ=../src/lib/krb5/krb/pac.o ../src/lib/krb5/krb/pac_sign.o ../src/lib/krb5/krb/copy_data.o
jsonOBJ=../src/util/support/json.o ../src/util/support/base64.o ../src/util/support/k5buf.o ../src/util/support/zap.o
profileOBJ=../src/util/profile/prof_tree.o ../src/util/profile/prof_file.o ../src/util/profile/prof_parse.o ../src/util/profile/prof_get.o ../src/util/profile/prof_set.o ../src/util/profile/prof_err.o ../src/util/profile/prof_init.o

all: $(TARGET)

#SETUP
$(TARGET):
	$(CC)  $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(ndrEXE).c
	$(CXX) $(CFLAGS) $(LibINC) -o $(ndrEXE) $(ndrEXE).o  $(ndrOBJ) $(LibFLAGS)

	$(CC)  $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(pacEXE).c
	$(CXX) $(CFLAGS) $(LibINC) -o $(pacEXE) $(pacEXE).o  $(pacOBJ) $(LibFLAGS)

	$(CC)  $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(chpwEXE).c
	$(CXX) $(CFLAGS) $(LibINC) -o $(chpwEXE) $(chpwEXE).o  $(LibFLAGS)

	$(CC)  $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(jsonEXE).c
	$(CXX) $(CFLAGS) $(LibINC) -o $(jsonEXE) $(jsonEXE).o  $(jsonOBJ) $(LibFLAGS)

	$(CC)  $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(marshalEXE).c
	$(CXX) $(CFLAGS) $(LibINC) -o $(marshalEXE) $(marshalEXE).o  $(LibFLAGS)

	$(CC)  $(CFLAGS) $(INC) $(EXTCFLAGS) -DHAS_STDARG -c $(profileEXE).c
	$(CXX) $(CFLAGS) $(LibINC) -o $(profileEXE) $(profileEXE).o  $(profileOBJ) $(LibFLAGS)

	$(CC)  $(CFLAGS) $(INC) $(EXTCFLAGS) -c $(rdreqEXE).c
	$(CXX) $(CFLAGS) $(LibINC) -o $(rdreqEXE) $(rdreqEXE).o  $(LibFLAGS)

clean:
	rm $(ndrEXE) $(pacEXE) $(chpwEXE) $(jsonEXE) $(marshalEXE) $(profileEXE) $(rdreqEXE) *.o

.PHONY: all clean
