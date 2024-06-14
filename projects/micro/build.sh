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

mv $SRC/parse_fuzzer.go ./util/router/

# This is a stripped version of OSS-fuzz's base builder
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
compile_go_fuzzer github.com/micro/micro/v3/util/router Fuzz fuzz
