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

# backup vtctl_fuzzer.go
cp go/test/fuzzing/vtctl_fuzzer.go /tmp/
rm -r go/test/fuzzing/*

mv $SRC/parser_fuzzer_test.go $SRC/vitess/go/test/fuzzing/
mv $SRC/ast_fuzzer_test.go $SRC/vitess/go/test/fuzzing/
mv $SRC/tablet_manager_fuzzer_test.go $SRC/vitess/go/test/fuzzing/


# Disable logging for mysql conn
# This affects the mysql fuzzers
sed -i '/log.Errorf/c\\/\/log.Errorf' $SRC/vitess/go/mysql/conn.go
sed -i '/log.Warningf/c\\/\/log.Warningf' $SRC/vitess/go/vt/sqlparser/parser.go

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

# build_go_fuzz_harness rewrites a copy of the 
# fuzzer to allow for libFuzzer instrumentation
function rewrite_go_fuzz_harness() {
	fuzzer_filename=$1

        # Create a copy of the fuzzer to not modify the existing fuzzer
        cp $fuzzer_filename "${fuzzer_filename}"_fuzz_.go
	mv $fuzzer_filename /tmp/

        # replace *testing.F with *go118fuzzbuildutils.F
        echo "replacing *testing.F"
        sed -i 's/f \*testing\.F/f \*go118fuzzbuildutils\.F/g' "${fuzzer_filename}"_fuzz_.go

        # import https://github.com/AdamKorcz/go-118-fuzz-build
        # This changes the line numbers from the original fuzzer
	$SRC/go-118-fuzz-build/addimport/addimport -path "${fuzzer_filename}"_fuzz_.go
}

function compile_native_go_fuzzer() {
	fuzzer=$1
	function=$2
	path=$3
	tags="-tags gofuzz"

	if [[ $SANITIZER = *coverage* ]]; then
		echo "here we perform coverage build"
		fuzzed_package=`go list $tags -f '{{.Name}}' $path`
		abspath=`go list $tags -f {{.Dir}} $path`
		cd $abspath
		cp $SRC/native_ossfuzz_coverage_runnger.go ./"${function,,}"_test.go
		sed -i -e 's/FuzzFunction/'$function'/' ./"${function,,}"_test.go
		sed -i -e 's/mypackagebeingfuzzed/'$fuzzed_package'/' ./"${function,,}"_test.go
		sed -i -e 's/TestFuzzCorpus/Test'$function'Corpus/' ./"${function,,}"_test.go

		# The repo is the module path/name, which is already created above in case it doesn't exist,
		# but not always the same as the module path. This is necessary to handle SIV properly.
		fuzzed_repo=$(go list $tags -f {{.Module}} "$path")
		abspath_repo=`go list -m $tags -f {{.Dir}} $fuzzed_repo || go list $tags -f {{.Dir}} $fuzzed_repo`
		# give equivalence to absolute paths in another file, as go test -cover uses golangish pkg.Dir
		echo "s=$fuzzed_repo"="$abspath_repo"= > $OUT/$fuzzer.gocovpath
		ls
		gotip test -run Test${function}Corpus -v $tags -coverpkg $fuzzed_repo/... -c -o $OUT/$fuzzer $path
		
		rm ./"${function,,}"_test.go
	else
	        $SRC/go-118-fuzz-build/go-118-fuzz-build -o $fuzzer.a -func $function $abs_file_dir
        	$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.a -o $OUT/$fuzzer
	fi
}

# build_go_fuzzer will be the api used by users
# The api is now placed in this build script
# but will be moved to the base image once it
# has reached sufficient maturity.
function build_go_fuzzer () {
        path=$1
        function=$2
	fuzzer=$3
        tags="-tags gofuzz"

        # Get absolute path
        abs_file_dir=$(go list $tags -f {{.Dir}} $path)

        # TODO: Get rid of "-r" flag here
        fuzzer_filename=$(grep -r -l  -s "$function" "${abs_file_dir}")
	
	# test if file contains a line with "func $function" and "testing.F"
	if [ $(grep -r "func $function" $fuzzer_filename | grep "testing.F" | wc -l) -eq 1 ]
	then
		# we are dealing with a native harness

	        # Install more dependencies
		gotip get github.com/AdamKorcz/go-118-fuzz-build/utils
		gotip get google.golang.org/grpc/internal/channelz@v1.39.0
	
		echo "Native harness"
		rewrite_go_fuzz_harness $fuzzer_filename
		compile_native_go_fuzzer $fuzzer $function $abs_file_dir
		# clean up
		rm "${fuzzer_filename}_fuzz_.go"
		mv /tmp/$(basename $fuzzer_filename) $fuzzer_filename
	else
		# we are dealing with a go-fuzz harness
		echo "go-fuzz harness"
		compile_go_fuzzer $path $function $fuzzer $tags
	fi
	
}

# build native fuzzers
build_go_fuzzer vitess.io/vitess/go/test/fuzzing FuzzTabletManager_ExecuteFetchAsDba fuzz_tablet_manager_execute_fetch_as_dba
build_go_fuzzer vitess.io/vitess/go/test/fuzzing FuzzParser parser_fuzzer
build_go_fuzzer vitess.io/vitess/go/test/fuzzing FuzzIsDML is_dml_fuzzer
build_go_fuzzer vitess.io/vitess/go/test/fuzzing FuzzNormalizer normalizer_fuzzer
build_go_fuzzer vitess.io/vitess/go/test/fuzzing FuzzNodeFormat normalizer_fuzzer
build_go_fuzzer vitess.io/vitess/go/test/fuzzing FuzzSplitStatementToPieces fuzz_split_statement_to_pieces
build_go_fuzzer vitess.io/vitess/go/test/fuzzing FuzzEqualsSQLNode fuzz_equals_sql_node

# Delete all the native fuzzers before building the go-fuzz fuzzer(s)
# this will not be necessary when Go 1.18 is released. The reason this
# is needed is because go114-fuzz-build calls "go" instead of "gotip",
# and an error will be thrown because testing.F is not recognized.
rm $SRC/vitess/go/test/fuzzing/*_test.go

# build go-fuzz fuzzers
mv /tmp/vtctl_fuzzer.go $SRC/vitess/go/test/fuzzing/
build_go_fuzzer vitess.io/vitess/go/test/fuzzing Fuzz vtctl_fuzzer

