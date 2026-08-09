all: fuzzer

fuzzer:
	$(CC) $(CFLAGS) $(EXTCFLAGS) -I../include -I../src -c fuzz-accept-sec-context.c
	$(CXX) $(CFLAGS) -o fuzz-accept-sec-context fuzz-accept-sec-context.o ../.libs/gssntlmssp.a $(LIB_FUZZING_ENGINE) -lssl -lcrypto -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err -lunistring -lz
