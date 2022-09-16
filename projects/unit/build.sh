./configure --debug --tests --no-regex --no-pcre2
make all

pushd fuzzer/
make
cp Fuzz_http $OUT/Fuzz_http
cp Fuzz_clone $OUT/Fuzz_clone
popd
