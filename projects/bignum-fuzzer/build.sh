cd $SRC/openssl
if [[ $CFLAGS = *sanitize=memory* ]]
then
  CFLAGS+=" -DOPENSSL_NO_ASM=1"
fi
./config $CFLAGS
make -j$(nproc)

# Build OpenSSL module
cd $SRC/bignum-fuzzer/modules/openssl
OPENSSL_INCLUDE_PATH=$SRC/openssl/include OPENSSL_LIBCRYPTO_A_PATH=$SRC/openssl/libcrypto.a make

# Build Go module
cd $SRC/bignum-fuzzer/modules/go
make

CXXFLAGS+=" -DBNFUZZ_FLAG_NO_NEGATIVE=1 -DBNFUZZ_FLAG_NUM_LEN=1200 -DBNFUZZ_FLAG_ALL_OPERATIONS=1"

# Build fuzzer
cd $SRC/bignum-fuzzer
./config-modules.sh openssl go
LIBFUZZER_LINK="-lFuzzingEngine" make

cd $SRC

# Copy fuzzer to the designated location
cp $SRC/bignum-fuzzer/fuzzer $OUT/fuzzer_openssl_go_no_negative_num_len_1200_all_operations


# Copy seed corpus to the designated location
cp $SRC/bignum-fuzzer/corpora/fuzzer_openssl_go_no_negative_num_len_1200_all_operations_seed_corpus.zip $OUT
