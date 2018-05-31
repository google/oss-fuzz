cd $SRC/openssl
if [[ $CFLAGS = *sanitize=memory* ]]
then
  CFLAGS+=" -DOPENSSL_NO_ASM=1"
fi
./config
make -j$(nproc)

# Build OpenSSL module
cd $SRC/bignum-fuzzer/modules/openssl
OPENSSL_INCLUDE_PATH=$SRC/openssl/include OPENSSL_LIBCRYPTO_A_PATH=$SRC/openssl/libcrypto.a make

# Build Go module
cd $SRC/bignum-fuzzer/modules/go
make

# Build Rust module
cd $SRC/bignum-fuzzer/modules/rust
make

# Build C++-Boost module
cd $SRC/bignum-fuzzer/modules/cpp_boost
make

BASE_CXXFLAGS=$CXXFLAGS

# Build OpenSSL/Go fuzzer
cd $SRC/bignum-fuzzer
./config-modules.sh openssl go
CXXFLAGS="$BASE_CXXFLAGS -DBNFUZZ_FLAG_NO_NEGATIVE=1 -DBNFUZZ_FLAG_NUM_LEN=1200 -DBNFUZZ_FLAG_ALL_OPERATIONS=1"
LIBFUZZER_LINK="-lFuzzingEngine" make

# Copy OpenSSL/Go fuzzer to the designated location
cp $SRC/bignum-fuzzer/fuzzer $OUT/fuzzer_openssl_go_no_negative_num_len_1200_all_operations

# Build OpenSSL/Rust fuzzer
cd $SRC/bignum-fuzzer
make clean
./config-modules.sh openssl rust
CXXFLAGS="$BASE_CXXFLAGS -DBNFUZZ_FLAG_NUM_LEN=1200 -DBNFUZZ_FLAG_ALL_OPERATIONS=1 -DBNFUZZ_FLAG_NUM_LOOPS=1"
LIBFUZZER_LINK="-lFuzzingEngine" make

# Copy OpenSSL/Rust fuzzer to the designated location
cp $SRC/bignum-fuzzer/fuzzer $OUT/fuzzer_openssl_rust_num_len_1200_all_operations_num_loops_1

# Build OpenSSL/C++-Boost fuzzer
cd $SRC/bignum-fuzzer
make clean
./config-modules.sh openssl cpp_boost
CXXFLAGS="$BASE_CXXFLAGS -DBNFUZZ_FLAG_NUM_LEN=1200 -DBNFUZZ_FLAG_ALL_OPERATIONS=1 -DBNFUZZ_FLAG_NUM_LOOPS=1"
LIBFUZZER_LINK="-lFuzzingEngine" make

# Copy OpenSSL/C++-Boost fuzzer to the designated location
cp $SRC/bignum-fuzzer/fuzzer $OUT/fuzzer_openssl_cpp_boost_num_len_1200_all_operations_num_loops_1

# Copy seed corpora to the designated location
cp $SRC/bignum-fuzzer/corpora/fuzzer_openssl_go_no_negative_num_len_1200_all_operations_seed_corpus.zip $OUT
cp $SRC/bignum-fuzzer/corpora/fuzzer_openssl_rust_num_len_1200_all_operations_num_loops_1_seed_corpus.zip $OUT
cp $SRC/bignum-fuzzer/corpora/fuzzer_openssl_cpp_boost_num_len_1200_all_operations_num_loops_1_seed_corpus.zip $OUT
