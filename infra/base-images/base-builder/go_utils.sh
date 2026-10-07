#!/bin/bash -eu
# Copyright 2025 Google LLC
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

# Adds a fuzzer to a json list stored in $OUT
# so we can easily check later if a fuzzer
# is a std lib fuzzer
add_to_list_of_native_fuzzers() {
  local new_element="$1"
  local file="$OUT/native_go_fuzzers.json"

  if [ -z "$new_element" ]; then
    echo "Usage: add_to_list \"element to add\""
    return 1
  fi

  # Ensure the directory exists
  if [ ! -d "$(dirname "$file")" ]; then
    echo "Error: Directory $(dirname "$file") does not exist."
    return 1
  fi

  # Initialize the file if it doesn't exist or is empty
  if [ ! -s "$file" ]; then
    echo "[]" > "$file"
  fi

  # Append the new element to the list using jq
  jq --arg item "$new_element" '. += [$item]' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
}

# Save a key-value pair to a JSON file. We use this to
# store the fuzzer function name with the fuzzer
# executable name; we need the function name in the
# coverage build.
save_function_name() {
  local key="$1"
  local value="$2"
  local file="$3"

  if [ -z "$key" ] || [ -z "$value" ] || [ -z "$file" ]; then
    echo "Usage: save_function_name <key> <value> <file>"
    return 1
  fi

  # If file doesn't exist or is empty, initialize it as empty object
  if [ ! -s "$file" ]; then
    echo "{}" > "$file"
  fi

  # Update or add the key-value pair
  jq --arg k "$key" --arg v "$value" '.[$k] = $v' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
}

function build_native_go_fuzzer_legacy() {
	fuzzer=$1
	function=$2
	path=$3
	tags="-tags gofuzz"

	if [[ $SANITIZER == *coverage* ]]; then
		current_dir=$(pwd)
		mkdir $OUT/rawfuzzers || true
		cd $abs_file_dir
		go test $tags -c -run $fuzzer -o $OUT/$fuzzer -cover
		cp "${fuzzer_filename}" "${OUT}/rawfuzzers/${fuzzer}"

		fuzzed_repo=$(go list $tags -f {{.Module}} "$path")
		abspath_repo=`go list -m $tags -f {{.Dir}} $fuzzed_repo || go list $tags -f {{.Dir}} $fuzzed_repo`
		# give equivalence to absolute paths in another file, as go test -cover uses golangish pkg.Dir
		echo "s=$fuzzed_repo"="$abspath_repo"= > $OUT/$fuzzer.gocovpath
		cd $current_dir
	else
		go-118-fuzz-build $tags -o $fuzzer.a -func $function $abs_file_dir
		$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.a -o $OUT/$fuzzer
	fi
}

function build_native_go_fuzzer() {
	fuzzer=$1
	function=$2
	abs_path=$3
	package_path=$4
	tags="-tags gofuzz"

	if [[ $SANITIZER == *coverage* ]]; then
		function_names_file="$OUT/fuzzer_function_names.json"

		# Save the current dir to return later
		current_dir=$(pwd)
		fuzzed_repo=$(go list $tags -f {{.Module}} "$abs_path")
		cd $abs_file_dir
		go test $tags \
	    -c \
	    -o "$OUT/$fuzzer" \
	    -coverpkg="$fuzzed_repo/..." \
	    -covermode=atomic \
	    "$package_path"
		save_function_name "$fuzzer" "$function" "$function_names_file"

		abspath_repo=`go list -m $tags -f {{.Dir}} $fuzzed_repo || go list $tags -f {{.Dir}} $fuzzed_repo`
		# give equivalence to absolute paths in another file, as go test -cover uses golangish pkg.Dir
		echo "s=$fuzzed_repo"="$abspath_repo"= > $OUT/$fuzzer.gocovpath
		add_to_list_of_native_fuzzers "${fuzzer}"

		# Store the function signature in $OUT/fuzzer-parameters.json
		# so we can read it when running helper.py coverage. We need
		# this to convert corpus to a readable format by the test.
		convertLibFuzzerTestcaseToStdLibGo \
		  -write-params \
		  -file $fuzzer_filename \
		  -fuzzer-func $function \
		  -fuzzerBinaryName $fuzzer \
		  -json-out $OUT/fuzzer-parameters.json
		cd $current_dir
	else
		go-118-fuzz-build_v2 $tags -o $fuzzer.a -func $function $abs_file_dir
		$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.a -o $OUT/$fuzzer
	fi
}
