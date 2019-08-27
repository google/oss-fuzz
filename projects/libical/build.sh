$WORK/cmake-3.14.3-Linux-x86_64/bin/cmake . -DSTATIC_ONLY=ON -DICAL_GLIB=False
make install -j$(nproc)

$CXX $CXXFLAGS -std=c++11 $SRC/libical_fuzzer.cc $LIB_FUZZING_ENGINE /usr/local/lib/libical.a -o $OUT/libical_fuzzer

find . -name *.ics -print | zip -q $OUT/libical_fuzzer_seed_corpus.zip -@
