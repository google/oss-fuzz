function compile_fuzzer {
    fuzzer=$(basename $1)

    # Instrument all Go files relevant to this fuzzer, compile and store in $fuzzer.a
    go-fuzz-build -libfuzzer -o $fuzzer.a github.com/dvyukov/go-fuzz-corpus/$fuzzer

    # Instrumented, compiled Go ($fuzzer.a) + libFuzzer = fuzzer binary
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.a -lpthread -o fuzzer-$fuzzer

    # Copy the fuzzer binary
    cp fuzzer-$fuzzer $OUT

    # Pack the seed corpus
    zip -r fuzzer-${fuzzer}_seed_corpus.zip \
        $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/$fuzzer/corpus

    # Copy the seed corpus
    cp fuzzer-${fuzzer}_seed_corpus.zip $OUT
}

export -f compile_fuzzer

# Use this to attempt to compile all
#find $SRC/go-fuzz-corpus -mindepth 1 -maxdepth 1 -type d -exec bash -c 'compile_fuzzer "$@"' bash {} \;

compile_fuzzer asn1
#compile_fuzzer bzip2
compile_fuzzer csv
compile_fuzzer elliptic
compile_fuzzer flate
compile_fuzzer fmt
#compile_fuzzer gif
compile_fuzzer gzip
compile_fuzzer httpreq
compile_fuzzer httpresp
compile_fuzzer jpeg
compile_fuzzer json
compile_fuzzer lzw
compile_fuzzer mime
compile_fuzzer multipart
compile_fuzzer png
compile_fuzzer tar
compile_fuzzer time
#compile_fuzzer url
compile_fuzzer xml
compile_fuzzer zip
compile_fuzzer zlib

