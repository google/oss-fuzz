#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

cd $SRC
# Build main binary
git clone https://github.com/AdamKorcz/go-118-fuzz-build
cd go-118-fuzz-build
go build

# Build addimport binary
cd addimport
go build

cd $SRC/vitess

# Remove existing non-native fuzzers to not deal with them
rm go/vt/vtgate/vindexes/fuzz.go
rm -r go/test/fuzzing/*

mv $SRC/parser_fuzzer_test.go $SRC/vitess/go/test/fuzzing/
mv $SRC/ast_fuzzer_test.go $SRC/vitess/go/test/fuzzing/
mv $SRC/tablet_manager_fuzzer_test.go $SRC/vitess/go/test/fuzzing/


# Disable logging for mysql conn
# This affects the mysql fuzzers
sed -i '/log.Errorf/c\\/\/log.Errorf' $SRC/vitess/go/mysql/conn.go

mv ./go/vt/vttablet/tabletmanager/vreplication/framework_test.go \
   ./go/vt/vttablet/tabletmanager/vreplication/framework_fuzz.go

#consistent_lookup_test.go is needed for loggingVCursor
mv ./go/vt/vtgate/vindexes/consistent_lookup_test.go \
   ./go/vt/vtgate/vindexes/consistent_lookup_test_fuzz.go

# fake_vcursor_test.go is needed for loggingVCursor
mv ./go/vt/vtgate/engine/fake_vcursor_test.go \
    ./go/vt/vtgate/engine/fake_vcursor.go

# plan_test.go is needed for vschemaWrapper
mv ./go/vt/vtgate/planbuilder/plan_test.go \
    ./go/vt/vtgate/planbuilder/plan_test_fuzz.go

# tabletserver fuzzer
mv ./go/vt/vttablet/tabletserver/testutils_test.go \
   ./go/vt/vttablet/tabletserver/testutils_fuzz.go

# collation fuzzer
mv ./go/mysql/collations/uca_test.go \
   ./go/mysql/collations/uca_test_fuzz.go

mv $SRC/vitess/go/vt/vtgate/grpcvtgateconn/suite_test.go \
	   $SRC/vitess/go/vt/vtgate/grpcvtgateconn/suite_test_fuzz.go
mv $SRC/vitess/go/vt/vtgate/grpcvtgateconn/fuzz_flaky_test.go \
	   $SRC/vitess/go/vt/vtgate/grpcvtgateconn/fuzz.go


# compile_native_go_fuzzer will be the api used by users
# similar to compile_go_fuzzer. The api is now placed in
# this build script but will be moved to the base image
# once it has reached sufficient maturity.
function compile_native_go_fuzzer () {
        path=$1
        function=$2
        tags="-tags gofuzz"

        # Get absolute path
        abs_file_dir=$(go list $tags -f {{.Dir}} $path)

        # Check if there are more than 1 function named $function
        number_of_occurences=$(grep -s "$function" $abs_file_dir/{*,.*} | wc -l)
        echo $number_of_occurences
        if [ $number_of_occurences -ne 1 ]
        then
                echo "Found multiple targets '$function' in $path"
                exit 0
        else
                echo "GREAT! Only a single target was found"
        fi

        # TODO: Get rid of "-r" flag here
        fuzzer_filename=$(grep -r -l  -s "$function" "${abs_file_dir}")

        # Create a copy of the fuzzer to not modify the existing fuzzer
        cp $fuzzer_filename "${fuzzer_filename}"_fuzz_.go

        # replace *testing.F with *go118fuzzbuildutils.F
        echo "replacing *testing.F"
        sed -i 's/f \*testing\.F/f \*go118fuzzbuildutils\.F/g' "${fuzzer_filename}"_fuzz_.go

        # import https://github.com/AdamKorcz/go-118-fuzz-build
        # This changes the line numbers from the original fuzzer
	$SRC/go-118-fuzz-build/addimport/addimport -path "${fuzzer_filename}"_fuzz_.go

        # Install more dependencies
        gotip get github.com/AdamKorcz/go-118-fuzz-build/utils
        gotip get google.golang.org/grpc/internal/channelz@v1.39.0

        $SRC/go-118-fuzz-build/go-118-fuzz-build -o fuzzer.a -func $function $abs_file_dir
        $CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzzer.a -o $OUT/$function
	
	# clean up
	rm "${fuzzer_filename}"_fuzz_.go
}

compile_native_go_fuzzer vitess.io/vitess/go/test/fuzzing FuzzTabletManager_ExecuteFetchAsDba
compile_native_go_fuzzer vitess.io/vitess/go/test/fuzzing FuzzParser
compile_native_go_fuzzer vitess.io/vitess/go/test/fuzzing FuzzIsDML
compile_native_go_fuzzer vitess.io/vitess/go/test/fuzzing FuzzNormalizer
compile_native_go_fuzzer vitess.io/vitess/go/test/fuzzing FuzzNodeFormat
compile_native_go_fuzzer vitess.io/vitess/go/test/fuzzing FuzzSplitStatementToPieces
compile_native_go_fuzzer vitess.io/vitess/go/test/fuzzing FuzzEqualsSQLNode
