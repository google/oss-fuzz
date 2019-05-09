# Compile latest Go
cd go/src
./make.bash
cd $SRC

# Remove previous Go install (used for bootstrapping)
apt-get remove golang-1.9-go -y
rm /usr/bin/go

export GOROOT=`realpath go`
export GOPATH=$GOROOT/packages
export PATH=$GOROOT/bin:$PATH

# Dependency of go-fuzz
go get golang.org/x/tools/go/packages

# go-fuzz-build is the tool that instruments Go files
go build github.com/dvyukov/go-fuzz/go-fuzz-build

function compile_fuzzer {
    fuzzer=$(basename $1)

    # Instrument all Go files relevant to this fuzzer, compile and store in $fuzzer.a
    ./go-fuzz-build -libfuzzer -o $fuzzer.a github.com/dvyukov/go-fuzz-corpus/$fuzzer

    # Instrumented, compiled Go ($fuzzer.a) + libFuzzer = fuzzer binary
    $CXX $CXXFLAGS -lFuzzingEngine $fuzzer.a -lpthread -o fuzzer-$fuzzer

    # Copy the fuzzer binary
    cp fuzzer-$fuzzer $OUT

    # Pack the seed corpus
    zip -r fuzzer-${fuzzer}_seed_corpus.zip $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/$fuzzer/corpus

    # Copy the seed corpus
    cp fuzzer-${fuzzer}_seed_corpus.zip $OUT
}

export -f compile_fuzzer

# Use this to attempt to compile all
#find $GOPATH/src/github.com/dvyukov/go-fuzz-corpus -mindepth 1 -maxdepth 1 -type d -exec bash -c 'compile_fuzzer "$@"' bash {} \;

compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/asn1
#compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/bzip2
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/csv
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/elliptic
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/flate
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/fmt
#compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/gif
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/gzip
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/httpreq
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/httpresp
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/jpeg
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/json
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/lzw
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/mime
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/multipart
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/png
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/tar
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/time
#compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/url
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/xml
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/zip
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/zlib
