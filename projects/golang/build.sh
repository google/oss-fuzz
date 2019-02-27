# Get golang
wget https://dl.google.com/go/go1.11.1.linux-amd64.tar.gz
tar zxvf go1.11.1.linux-amd64.tar.gz
export GOROOT=`realpath go`
export GOPATH=$GOROOT/packages
mkdir $GOPATH
export PATH=$GOROOT/bin:$PATH

go get github.com/guidovranken/golang-fuzzers/...
go get github.com/guidovranken/libfuzzer-go/...

go build github.com/guidovranken/libfuzzer-go/go-fuzz-build

$CC $CFLAGS -Wall -Wextra $GOPATH/src/github.com/guidovranken/libfuzzer-go/C/main_libFuzzer_extra_counters.c -g -O3 -c -o main.o
./go-fuzz-build -o encoding_json.a github.com/guidovranken/golang-fuzzers/encoding_json
$CXX $CXXFLAGS main.o encoding_json.a -lFuzzingEngine -lpthread -o fuzzer-encoding_json

cp fuzzer-encoding_json $OUT
