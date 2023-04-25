#!/bin/bash -eu
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# compile latest go from git
(
cd $SRC/goroot/src
./make.bash
)
rm -Rf /root/.go/
export PATH=$PATH:$SRC/goroot/bin/
go install golang.org/x/tools/cmd/goimports@latest

compile_package () {
    pkg=$1
    pkg_flat=`echo $pkg | sed 's/\//_/g' | sed 's/\./x'_$repo'/'`
    args=`cat $SRC/ngolo-fuzzing/x/args.txt | grep "^$pkg_flat " | cut -d" " -f2-`
    $SRC/ngolo-fuzzing/ngolo-fuzzing $args $pkg fuzz_ng_$pkg_flat
    # applies special python patcher if any
    ls $SRC/ngolo-fuzzing/x/$pkg_flat.py && (
        python3 $SRC/ngolo-fuzzing/x/$pkg_flat.py fuzz_ng_$pkg_flat/fuzz_ng.go > fuzz_ng_$pkg_flat/fuzz_ngp.go
        mv fuzz_ng_$pkg_flat/fuzz_ngp.go fuzz_ng_$pkg_flat/fuzz_ng.go
    )
    (
        cd fuzz_ng_$pkg_flat
        $SRC/LPM/external.protobuf/bin/protoc --go_out=./ ngolofuzz.proto
        mkdir cpp
        $SRC/LPM/external.protobuf/bin/protoc --cpp_out=./cpp ngolofuzz.proto
        $CXX -DNDEBUG -stdlib=libc++ -c -I . -I $SRC/LPM/external.protobuf/include cpp/ngolofuzz.pb.cc
        $CXX $CXXFLAGS -c -Icpp -I $SRC/libprotobuf-mutator/ -I $SRC/LPM/external.protobuf/include $SRC/ngolo-fuzzing/lpm/ngolofuzz.cc
    )
    if [ "$SANITIZER" = "coverage" ]
    then
        (
        cd fuzz_ng_$pkg_flat
        compile_go_fuzzer . FuzzNG_unsure fuzz_ngo_$pkg_flat
        )
    else
        (
        cd fuzz_ng_$pkg_flat
        compile_go_fuzzer . FuzzNG_unsure fuzz_ngo_$pkg_flat
        rm fuzz_ngo_$pkg_flat.a
        )
        $SRC/ngolo-fuzzing/go114-fuzz-build/go114-fuzz-build -func FuzzNG_valid -o fuzz_ng_$pkg_flat.a ./fuzz_ng_$pkg_flat

        $CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_ng_$pkg_flat/ngolofuzz.pb.o fuzz_ng_$pkg_flat//ngolofuzz.o fuzz_ng_$pkg_flat.a  $SRC/LPM/src/libfuzzer/libprotobuf-mutator-libfuzzer.a $SRC/LPM/src/libprotobuf-mutator.a $SRC/LPM/external.protobuf/lib/libprotobuf.a -o $OUT/fuzz_ng_$pkg_flat
        rm fuzz_ng_$pkg_flat.a
    fi
    (
        # corpus
        cp $SRC/ngolo-fuzzing/corpus/ngolo_helper.go fuzz_ng_$pkg_flat/
        goimports -w fuzz_ng_$pkg_flat/copy/*.go
        cp fuzz_ng_$pkg_flat/copy/*.go fuzz_ng_$pkg_flat/
        cp $pkg/*_test.go fuzz_ng_$pkg_flat/
        sed -i -e 's/^package .*/package 'fuzz_ng_$pkg_flat'/' fuzz_ng_$pkg_flat/*.go
        export FUZZ_NG_CORPUS_DIR=`pwd`/fuzz_ng_$pkg_flat/corpus/
        pushd fuzz_ng_$pkg_flat
        go mod tidy
        go test -mod=readonly
        zip -r $OUT/fuzz_ngo_"$pkg_flat"_seed_corpus.zip corpus
        popd
    )
}

# in $SRC/ngolo-fuzzing
go build

(
cd go114-fuzz-build
go build
)

touch $SRC/ko.txt
# compile x packages
cd $SRC/x
ls | while read repo; do
cd $repo
find . -type d | while read pkg; do
    if [[ `ls $pkg/*.go | wc -l` == '0' ]]; then
        continue
    fi
    if [[ `echo $pkg | grep internal | wc -l` == '1' ]]; then
        continue
    fi
    if [[ `echo $pkg | grep vendor | wc -l` == '1' ]]; then
        continue
    fi
    if [[ `echo $pkg | grep testdata | wc -l` == '1' ]]; then
        continue
    fi
    if compile_package $pkg $repo; then
        echo $repo/$pkg >> $SRC/ok.txt
    else
        echo "Failed for $pkg"
        echo $repo/$pkg >> $SRC/ko.txt
    fi

done
cd -
done

echo "Failed packages:"
cat $SRC/ko.txt

echo "Succesful packages:"
cat $SRC/ok.txt
