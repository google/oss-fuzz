cd $SRC/libsrtp
autoreconf -ivf
./configure
LIBFUZZER="$LIB_FUZZING_ENGINE" make srtp-fuzzer
zip -r srtp-fuzzer_seed_corpus.zip fuzzer/corpus
cp $SRC/libsrtp/fuzzer/srtp-fuzzer $OUT
cp srtp-fuzzer_seed_corpus.zip $OUT
