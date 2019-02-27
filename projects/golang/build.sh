# Get golang
wget https://dl.google.com/go/go1.11.1.linux-amd64.tar.gz
tar zxvf go1.11.1.linux-amd64.tar.gz
export GOROOT=`realpath go`
export GOPATH=$GOROOT/packages
mkdir $GOPATH
export PATH=$GOROOT/bin:$PATH

mkdir -p $GOPATH/src/github.com/dvyukov/
cd $GOPATH/src/github.com/dvyukov/
git clone https://github.com/dvyukov/go-fuzz-corpus
cd -
go get github.com/guidovranken/libfuzzer-go/...

go build github.com/guidovranken/libfuzzer-go/go-fuzz-build

function compile_fuzzer {
    fuzzer=$(basename $1)
    echo "Fuzzer is $fuzzer"
    $CC $CFLAGS -Wall -Wextra $GOPATH/src/github.com/guidovranken/libfuzzer-go/C/main_libFuzzer_extra_counters.c -g -O3 -c -o main.o
    ./go-fuzz-build -o $fuzzer.a github.com/dvyukov/go-fuzz-corpus/$fuzzer
    $CXX $CXXFLAGS main.o $fuzzer.a -lFuzzingEngine -lpthread -o fuzzer-$fuzzer
    cp fuzzer-$fuzzer $OUT
    zip -r fuzzer-${fuzzer}_seed_corpus.zip $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/$fuzzer/corpus
    cp fuzzer-${fuzzer}_seed_corpus.zip $OUT
}

export -f compile_fuzzer

# Use this to attempt to compile all
#find $GOPATH/src/github.com/dvyukov/go-fuzz-corpus -mindepth 1 -maxdepth 1 -type d -exec bash -c 'compile_fuzzer "$@"' bash {} \;

compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/asn1
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/gif
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/gzip
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/jpeg
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/json
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/lzw
compile_fuzzer $GOPATH/src/github.com/dvyukov/go-fuzz-corpus/png
