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

cd pkg
go mod download

if [[ $SANITIZER = *coverage* ]]; then
  compile_go_fuzzer()
  {
  path=$1
  function=$2
  fuzzer=$3
  tags="-tags gofuzz"
  if [[ $#  -eq 4 ]]; then
    tags="-tags $4"
  fi

  go mod download
  fuzzed_package=`go list $tags -f '{{.Name}}' $path`
  abspath=`go list $tags -f {{.Dir}} $path`
  cd $abspath
  cp $GOPATH/ossfuzz_coverage_runner.go ./"${function,,}"_test.go
  sed -i -e 's/FuzzFunction/'$function'/' ./"${function,,}"_test.go
  sed -i -e 's/mypackagebeingfuzzed/'$fuzzed_package'/' ./"${function,,}"_test.go
  sed -i -e 's/TestFuzzCorpus/Test'$function'Corpus/' ./"${function,,}"_test.go

  fuzzed_repo=$(go list $tags -f {{.Module}} "$path")
  abspath_repo=`go list -m $tags -f {{.Dir}} $fuzzed_repo || go list $tags -f {{.Dir}} $fuzzed_repo`
  echo "s=$fuzzed_repo"="$abspath_repo"= > $OUT/$fuzzer.gocovpath
  go test -run Test${function}Corpus -v $tags -coverpkg $fuzzed_repo/... -c -o $OUT/$fuzzer $path
  } 
fi

cp $SRC/schema_fuzzer.go $SRC/pulumi/pkg/codegen/schema/ 
compile_go_fuzzer github.com/pulumi/pulumi/pkg/v3/codegen/schema SchemaFuzzer schema_fuzzer

cp $SRC/config_fuzzer.go $SRC/pulumi/sdk/go/common/resource/config/
compile_go_fuzzer github.com/pulumi/pulumi/sdk/v3/go/common/resource/config FuzzConfig fuzz
compile_go_fuzzer github.com/pulumi/pulumi/sdk/v3/go/common/resource/config FuzzParseKey fuzz_parse_key