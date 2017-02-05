#!/bin/bash -eu

set -x

pushd $SRC/h2o
cmake -DBUILD_FUZZER=ON -DOSS_FUZZ=ON -DOPENSSL_USE_STATIC_LIBS=TRUE .
make
cp ./h2o-fuzzer-http* $OUT/

zip -jr $OUT/h2o-fuzzer-http1_seed_corpus.zip $SRC/h2o/fuzz/http1-corpus
zip -jr $OUT/h2o-fuzzer-http2_seed_corpus.zip $SRC/h2o/fuzz/http2-corpus

cp $SRC/*.options $SRC/h2o/fuzz/*.dict $OUT/
popd
